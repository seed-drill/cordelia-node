//! What one connection can make a node hold through the kernel's receive
//! batching of UDP (GRO), measured with a counting allocator (decision
//! 2026-10-22, memory across connections, rule 10, test 8).
//!
//! With GRO on, the kernel hands a socket a batch of a peer's datagrams in
//! one buffer, and quinn splits it into packets that share it: a stream
//! frame of one byte that the node does not read keeps the whole batch,
//! where quinn's reassembler counts one packet. A node turns GRO off on
//! its socket (`transport::create_endpoint`), so each frame keeps its own
//! datagram only.
//!
//! The peer is a quinn client whose socket gathers quinn's datagrams to
//! one destination into sends of `GATHERED` datagrams of one size (GSO):
//! stock quinn sends at most 10 a batch, too few to tell GRO on from off.
//! It sends bulk on one stream that the node reads, and one byte at a time
//! on every other stream it may open, which the node does not read. The
//! node runs on a current-thread runtime of its own, on a thread of its
//! own, and only that thread's heap is counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use cordelia_core::protocol;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_network::transport;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};

// ── A counting allocator, by thread ─────────────────────────────────

struct Counting;

thread_local! {
    /// The bytes this thread holds: asked for and not given back.
    static LIVE: Cell<isize> = const { Cell::new(0) };
    /// The most it has held since the peak was last set to what it holds.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn counted(bytes: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + bytes;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc_zeroed(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        unsafe { System.dealloc(at, layout) };
        counted(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, at: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(at, layout, size) };
        if !moved.is_null() {
            counted(size as isize - layout.size() as isize);
        }
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn live() -> isize {
    LIVE.with(Cell::get)
}

/// Set this thread's peak to what it holds now.
fn peak_from_now() {
    PEAK.with(|peak| peak.set(live()));
}

fn peak() -> isize {
    PEAK.with(Cell::get)
}

// ── The peer's socket: quinn's datagrams gathered into GSO sends ───────

/// How many datagrams of one size the peer's socket gathers into one send.
const GATHERED: usize = 44;

/// How long a datagram may wait to be gathered before it is sent with
/// those beside it: long enough that the bulk of one stream, a stream's
/// window at a time, fills batches of `GATHERED`.
const GATHER_WAIT: Duration = Duration::from_millis(10);

#[derive(Debug, Default)]
struct Gathering {
    destination: Option<SocketAddr>,
    size: usize,
    datagrams: usize,
    contents: Vec<u8>,
    since: Option<std::time::Instant>,
}

/// A UDP socket that holds the datagrams quinn sends to one destination
/// until `GATHERED` of one size are held, or `GATHER_WAIT` has passed,
/// and sends them as one GSO send.
#[derive(Debug)]
struct Gatherer {
    inner: Arc<dyn AsyncUdpSocket>,
    held: Mutex<Gathering>,
}

impl Gatherer {
    fn send_held(&self, held: &mut Gathering) {
        if held.datagrams == 0 {
            return;
        }
        let transmit = Transmit {
            destination: held.destination.expect("held datagrams have a destination"),
            ecn: None,
            contents: &held.contents,
            segment_size: (held.datagrams > 1).then_some(held.size),
            src_ip: None,
        };
        // A send the kernel refuses is a datagram lost, which QUIC sends
        // again.
        let _ = self.inner.try_send(&transmit);
        held.contents.clear();
        held.datagrams = 0;
        held.since = None;
    }

    /// Send what has waited `GATHER_WAIT`.
    fn send_waited(&self) {
        let mut held = self.held.lock().unwrap();
        if held
            .since
            .is_some_and(|since| since.elapsed() >= GATHER_WAIT)
        {
            self.send_held(&mut held);
        }
    }
}

impl AsyncUdpSocket for Gatherer {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let size = transmit.segment_size.unwrap_or(transmit.contents.len());
        let mut held = self.held.lock().unwrap();
        for datagram in transmit.contents.chunks(size) {
            if held.datagrams > 0
                && (held.destination != Some(transmit.destination) || datagram.len() != held.size)
            {
                self.send_held(&mut held);
            }
            if held.datagrams == 0 {
                held.destination = Some(transmit.destination);
                held.size = datagram.len();
                held.since = Some(std::time::Instant::now());
            }
            held.contents.extend_from_slice(datagram);
            held.datagrams += 1;
            if held.datagrams >= GATHERED {
                self.send_held(&mut held);
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ── The node and the peer ───────────────────────────────────────────

/// How the node's endpoint is made.
#[derive(Clone, Copy, Debug)]
enum Node {
    /// As a node makes it: GRO off (`transport::create_endpoint`).
    AsANodeMakesIt,
    /// As quinn makes it by itself, with the node's settings: GRO on.
    AsQuinnMakesIt,
}

/// The most the node's thread held over its level once the connection
/// was open, while a peer sent bulk on one stream and a byte every
/// `pace` on each other stream, for `lasting`.
fn held_by_the_node(node: Node, pace: Duration, lasting: Duration) -> isize {
    let node_id = NodeIdentity::generate().unwrap();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let node_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let here: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let endpoint = match node {
                Node::AsANodeMakesIt => transport::create_endpoint(&node_id, here).unwrap(),
                Node::AsQuinnMakesIt => {
                    quinn::Endpoint::server(transport::server_config(&node_id).unwrap(), here)
                        .unwrap()
                }
            };
            addr_tx.send(endpoint.local_addr().unwrap()).unwrap();
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            // The bulk stream, the first the peer opens, is read; the
            // others are never accepted.
            let (_send, mut recv) = conn.accept_bi().await.unwrap();
            tokio::task::yield_now().await;
            let level = live();
            peak_from_now();
            let reading = async {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(Some(_)) = recv.read(&mut buf).await {}
            };
            tokio::select! {
                _ = reading => {}
                _ = done_rx => {}
            }
            let most = peak() - level;
            conn.close(0u32.into(), b"done");
            endpoint.close(0u32.into(), b"done");
            most
        })
    });

    let node_addr = addr_rx.recv().unwrap();
    let peer = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    peer.block_on(async move {
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gatherer = Arc::new(Gatherer {
            inner: runtime.wrap_udp_socket(socket).unwrap(),
            held: Mutex::new(Gathering::default()),
        });
        let sending = {
            let gatherer = Arc::downgrade(&gatherer);
            tokio::spawn(async move {
                while let Some(gatherer) = gatherer.upgrade() {
                    gatherer.send_waited();
                    drop(gatherer);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            gatherer,
            runtime,
        )
        .unwrap();
        let peer_id = NodeIdentity::generate().unwrap();
        endpoint.set_default_client_config(transport::client_config(&peer_id).unwrap());
        let conn = endpoint
            .connect(node_addr, "cordelia")
            .unwrap()
            .await
            .unwrap();

        let (mut bulk, _bulk_recv) = conn.open_bi().await.unwrap();
        bulk.write_all(b"b").await.unwrap();
        let until = tokio::time::Instant::now() + lasting;
        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(async move {
            let chunk = vec![7u8; 16 * 1024];
            while tokio::time::Instant::now() < until {
                if bulk.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        }));
        for _ in 1..protocol::QUIC_MAX_BIDI_STREAMS {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let _recv = recv;
                while tokio::time::Instant::now() < until {
                    if send.write_all(b"x").await.is_err() {
                        break;
                    }
                    tokio::time::sleep(pace).await;
                }
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
        let _ = done_tx.send(());
        conn.close(0u32.into(), b"done");
        sending.abort();
    });
    node_thread.join().unwrap()
}

/// The most one connection may make the node's thread hold over its
/// level here: 1,200 KiB. Measured on loopback, on change F's windows
/// (31.5 KiB a stream) and 8 streams, at five pacings of the one-byte
/// writes (1 to 16 ms), three times each: GRO off 330 to 711 KiB, GRO on
/// 1,828 to 3,022 KiB. The threshold lies between the two, near their
/// geometric mean. (At 36 KiB a stream: 357 to 656 and 2,238 to 3,292
/// KiB; at a small message a stream, four times each, 416 to 517 and
/// 4,601 to 6,627 KiB.)
const THRESHOLD_BYTES: isize = 1200 * 1024;

/// How many times the control is measured before the test says it
/// checked nothing. A busy host can leave one reading short of the
/// threshold (1,194 KiB on CI, where it is 1,828 KiB or more on a quiet
/// host): with twice as many busy processes as cores, 3 first readings in
/// 12 were short, 1,082 to 1,167 KiB, and each second reading was over. A
/// host that hands a socket no batches leaves every reading short, as
/// does one loaded far past its cores (four busy processes to a core:
/// every reading 989 to 1,182 KiB).
const CONTROL_TRIES: usize = 3;

/// Decision 2026-10-22, memory across connections, rule 10. A peer that
/// sends its datagrams in large GSO batches, bulk on a stream the node
/// reads and a byte at a time on its other streams, cannot make a node
/// hold the batches its bytes came in: the node's thread holds less than
/// THRESHOLD_BYTES over its level, at two pacings. The same peer against
/// an endpoint that quinn makes by itself, with GRO on, takes it over
/// first: that control shows that this host hands a socket batches and
/// that the peer loads them. It is measured again, up to `CONTROL_TRIES`
/// times, until one reading is over the threshold.
///
/// Where every reading of the control stays under the threshold, the test
/// checks nothing, and says so loudly on its output. Off CI it is not
/// failed, since that is a property of the host (a kernel without GRO, a
/// loopback that does not coalesce, or a machine too loaded for the peer
/// to fill its batches) and not of the node, and a node on such a host
/// takes no batches either.
/// On CI (where `CI` is set, as GitHub Actions sets it) it fails: CI is
/// where rule 10 is held to, and a run there that checked nothing must not
/// pass as one that did, as `msg_e2e.rs` fails without the binary of the
/// version before.
#[test]
fn a_peer_cannot_make_a_node_hold_its_batches_of_datagrams() {
    let lasting = Duration::from_secs(3);
    let mut readings = Vec::new();
    let with_gro = loop {
        let held = held_by_the_node(Node::AsQuinnMakesIt, Duration::from_millis(4), lasting);
        readings.push(held / 1024);
        if held >= THRESHOLD_BYTES || readings.len() == CONTROL_TRIES {
            break held;
        }
    };
    println!("the control held {readings:?} KiB");
    if with_gro < THRESHOLD_BYTES {
        let said = format!(
            "\n*** TEST 8 CHECKED NOTHING: with GRO on, the control held {readings:?} KiB \
             in {CONTROL_TRIES} tries, each under the threshold of {} KiB, so this host \
             hands a socket no batches (or is too loaded to fill them), and rule 10 was \
             not tested here ***\n",
            THRESHOLD_BYTES / 1024
        );
        // On both streams, so that it is seen whether or not the output
        // is captured.
        println!("{said}");
        eprintln!("{said}");
        assert!(
            std::env::var_os("CI").is_none(),
            "test 8 checked nothing on CI: {said}"
        );
        return;
    }
    for pace in [2u64, 8] {
        let held = held_by_the_node(Node::AsANodeMakesIt, Duration::from_millis(pace), lasting);
        assert!(
            held < THRESHOLD_BYTES,
            "at a byte every {pace} ms the node held {} KiB, where with GRO on it held {} KiB",
            held / 1024,
            with_gro / 1024
        );
    }
}

/// The figures, with GRO off and on, at five pacings. Run by hand:
/// `cargo test -p cordelia-network --test receive_batching -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, printed: run by hand"]
fn measure_with_and_without_receive_batching() {
    for pace in [1u64, 2, 4, 8, 16] {
        let pace = Duration::from_millis(pace);
        let off = held_by_the_node(Node::AsANodeMakesIt, pace, Duration::from_secs(3));
        let on = held_by_the_node(Node::AsQuinnMakesIt, pace, Duration::from_secs(3));
        println!(
            "pace {pace:?}: GRO off {} KiB, GRO on {} KiB",
            off / 1024,
            on / 1024
        );
    }
}
