//! Out-of-order vouchers inside a reorder window.

use super::*;
use crate::error::PaymentError;
use crate::protocol::methods::tempo::voucher::sign_voucher;
use alloy::signers::local::PrivateKeySigner;
use std::time::Duration;

const WINDOW_MS: u64 = 30_000;
const NOW: u64 = 1_000_000;

/// A channel whose highest accepted voucher is `highest`.
fn channel_at(highest: u128) -> ChannelState {
    let mut state = test_channel_state("0xchannel");
    state.highest_voucher_amount = highest;
    state.highest_voucher_signature = Some(vec![highest as u8]);
    state
}

fn accept(
    state: ChannelState,
    cumulative: u128,
    after: Option<u128>,
    now: u64,
) -> Result<ChannelState, VerificationError> {
    state.accept_voucher_in_window(cumulative, after, vec![cumulative as u8], 0, now, WINDOW_MS)
}

fn runs(state: &ChannelState) -> Vec<(u128, u128)> {
    state
        .window
        .as_ref()
        .unwrap()
        .runs
        .iter()
        .map(|run| (run.from, run.to))
        .collect()
}

/// Two concurrent requests sign 110 (after 100) and 120 (after 110); 120
/// lands first. Both are accepted and their increments merge into one run.
#[test]
fn reordered_vouchers_are_both_accepted() {
    let state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    assert_eq!(state.highest_voucher_amount, 120);
    assert_eq!(runs(&state), vec![(110, 120)]);

    let state = accept(state, 110, Some(100), NOW + 5).unwrap();
    assert_eq!(state.highest_voucher_amount, 120, "a late voucher leaves H");
    assert_eq!(state.highest_voucher_signature, Some(vec![120]));
    assert_eq!(runs(&state), vec![(100, 120)]);
    // The run keeps the age of the gap the late voucher filled.
    assert_eq!(state.window.as_ref().unwrap().runs[0].at, NOW);
}

/// Serial vouchers without `after` grow one run, as today's advance does.
#[test]
fn serial_vouchers_without_after_grow_one_run() {
    let mut state = channel_at(100);
    for cumulative in [110, 120, 130] {
        state = accept(state, cumulative, None, NOW).unwrap();
    }
    assert_eq!(state.highest_voucher_amount, 130);
    assert_eq!(runs(&state), vec![(100, 130)]);
}

/// Replaying any accepted voucher inside the window is refused as seen,
/// including an exact replay of the highest one, without naming the
/// channel's accepted or required amounts to whoever replayed it.
#[test]
fn replays_are_seen() {
    let state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    let state = accept(state, 110, Some(100), NOW).unwrap();

    for (cumulative, after) in [(120, Some(110)), (120, None), (110, Some(100)), (105, None)] {
        let err = accept(state.clone(), cumulative, after, NOW).unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::DeltaTooSmall));
        assert!(err.message.contains("(seen)"), "{}", err.message);
        assert!(!err.message.contains("120"), "{}", err.message);
        let json = serde_json::to_value(err.to_problem_details(None)).unwrap();
        assert!(json.get("acceptedCumulative").is_none(), "{json}");
        assert!(json.get("requiredCumulative").is_none(), "{json}");
    }
}

/// A channel that never used the window starts with its floor at the
/// highest voucher, so no voucher accepted before it can be replayed.
#[test]
fn vouchers_below_the_initial_floor_are_stale() {
    let err = accept(channel_at(100), 90, None, NOW).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
    let err = accept(channel_at(100), 100, Some(90), NOW).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
}

/// Runs older than the window raise the floor: a voucher delayed past it,
/// or replayed after it, is stale rather than seen, and never charged.
#[test]
fn vouchers_older_than_the_window_are_stale() {
    let state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    // The hole (100, 110] is open inside the window ...
    assert!(accept(state.clone(), 110, Some(100), NOW + WINDOW_MS - 1).is_ok());
    // ... and closed once the run above it is older than the window.
    let later = NOW + WINDOW_MS;
    let err = accept(state.clone(), 110, Some(100), later).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
    let err = accept(state.clone(), 120, Some(110), later).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);

    let state = accept(state, 130, Some(120), later).unwrap();
    assert_eq!(state.window.as_ref().unwrap().floor, 120);
    assert_eq!(runs(&state), vec![(120, 130)]);
}

/// `after` at or above the voucher's own amount is malformed.
#[test]
fn after_must_be_below_the_cumulative_amount() {
    for after in [120, 121] {
        let err = accept(channel_at(100), 120, Some(after), NOW).unwrap_err();
        assert_eq!(err.code, None);
        assert_eq!(err.message, "voucher after must be below cumulativeAmount");
    }
}

/// The minimum delta applies to a voucher's own increment, above the floor.
#[test]
fn min_delta_applies_to_the_vouchers_own_increment() {
    let state = channel_at(100);
    let err = state
        .clone()
        .accept_voucher_in_window(120, Some(115), vec![], 10, NOW, WINDOW_MS)
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::DeltaTooSmall));
    assert!(err.message.contains("voucher delta 5 below minimum 10"));
    // `after` below the floor counts only from the floor.
    let err = state
        .clone()
        .accept_voucher_in_window(105, Some(0), vec![], 10, NOW, WINDOW_MS)
        .unwrap_err();
    assert!(err.message.contains("voucher delta 5 below minimum 10"));
    assert!(state
        .accept_voucher_in_window(120, Some(110), vec![], 10, NOW, WINDOW_MS)
        .is_ok());
}

/// A lying `after` only changes which increment is marked seen: the
/// highest voucher, and so the funds, stay the same.
#[test]
fn a_wide_after_only_marks_more_as_seen() {
    let state = accept(channel_at(100), 120, Some(100), NOW).unwrap();
    assert_eq!(state.highest_voucher_amount, 120);
    let err = accept(state, 110, Some(105), NOW).unwrap_err();
    assert!(err.message.contains("(seen)"), "{}", err.message);
}

/// A run's `at` is when the gap below it opened: a run above every other
/// one opens it now, a run inside a gap keeps that gap's age, and runs that
/// touch merge into one with the lower run's age.
#[test]
fn runs_keep_the_age_of_the_gap_below_them() {
    let mut window = VoucherWindow::default();
    window.insert(10, 20, 1);
    window.insert(30, 40, 2);
    // Inside the gap below (10, 20], which opened at 1.
    window.insert(0, 5, 3);
    assert_eq!(
        window
            .runs
            .iter()
            .map(|run| (run.from, run.to, run.at))
            .collect::<Vec<_>>(),
        vec![(0, 5, 1), (10, 20, 1), (30, 40, 2)]
    );
    // Fills the gap below (30, 40] and merges all three into one run whose
    // gap below is the oldest.
    window.insert(20, 30, 4);
    // Extending the top run keeps its age.
    window.insert(40, 50, 5);
    assert_eq!(
        window.runs,
        vec![
            VoucherRun {
                from: 0,
                to: 5,
                at: 1
            },
            VoucherRun {
                from: 10,
                to: 50,
                at: 1
            }
        ]
    );
}

/// A lost voucher leaves a hole that expires a window after it opened, also
/// while in-order traffic keeps extending the run above it.
#[test]
fn a_hole_expires_under_continuous_traffic() {
    // 110 (after 100) is lost; 120 (after 110) opens the hole (100, 110].
    let mut state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    let mut cumulative = 120;
    let mut now = NOW;
    while now < NOW + 2 * WINDOW_MS {
        now += 1_000;
        if now < NOW + WINDOW_MS {
            assert!(
                accept(state.clone(), 110, Some(100), now).is_ok(),
                "the hole is open inside the window"
            );
        }
        state = accept(state, cumulative + 10, Some(cumulative), now).unwrap();
        cumulative += 10;
    }
    let err = accept(state.clone(), 110, Some(100), now).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
    // Vouchers still in flight above the old run are accepted as usual.
    let state = accept(state, cumulative + 20, Some(cumulative + 10), now).unwrap();
    assert!(accept(state, cumulative + 10, Some(cumulative), now).is_ok());
}

/// The window is persisted with the channel, and channels stored before it
/// existed still load.
#[test]
fn window_round_trips_through_serde() {
    let state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["window"]["floor"], 100);
    assert_eq!(json["window"]["runs"][0]["from"], 110);
    assert_eq!(json["window"]["runs"][0]["at"], NOW);
    let back: ChannelState = serde_json::from_value(json).unwrap();
    assert_eq!(back.window, state.window);

    let mut legacy = serde_json::to_value(channel_at(100)).unwrap();
    assert!(legacy.get("window").is_none());
    legacy.as_object_mut().unwrap().remove("window");
    let back: ChannelState = serde_json::from_value(legacy).unwrap();
    assert!(back.window.is_none());
}

async fn signed(signer: &PrivateKeySigner, channel_id: B256, amount: u128) -> String {
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    alloy::hex::encode_prefixed(
        sign_voucher(signer, channel_id, amount, escrow, 42431)
            .await
            .unwrap(),
    )
}

/// A session method with a reorder window accepts a late voucher that a
/// method without one refuses, and advertises the window.
#[tokio::test]
async fn session_method_with_reorder_window_accepts_late_vouchers() {
    let signer = PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let id = channel_id.parse::<B256>().unwrap();
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    let (low, high) = (
        signed(&signer, id, 2_000).await,
        signed(&signer, id, 3_000).await,
    );

    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state.clone());
    let serial = test_session_method(store.clone());
    assert!(serial.challenge_method_details().unwrap()["reorderWindow"].is_null());
    serial
        .verify_and_accept_voucher(&channel_id, None, 3_000, Some(2_000), &high, 0)
        .await
        .unwrap();
    let err = serial
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &low, 0)
        .await
        .unwrap_err();
    assert_eq!(err.message, "voucher does not add new funds");

    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state);
    let reordering = test_session_method(store.clone()).with_reorder_window(DEFAULT_REORDER_WINDOW);
    assert_eq!(
        reordering.challenge_method_details().unwrap()["reorderWindow"],
        30
    );
    reordering
        .verify_and_accept_voucher(&channel_id, None, 3_000, Some(2_000), &high, 0)
        .await
        .unwrap();
    let state = reordering
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &low, 0)
        .await
        .unwrap();
    assert_eq!(state.highest_voucher_amount, 3_000);
    assert_eq!(
        state
            .window
            .unwrap()
            .runs
            .iter()
            .map(|run| (run.from, run.to))
            .collect::<Vec<_>>(),
        vec![(1_000, 3_000)]
    );
    // Requests are charged from the highest voucher, as before.
    let charged = deduct_from_channel(&*store, &channel_id, 2_000)
        .await
        .unwrap();
    assert_eq!(charged.spent, 2_000);

    // A replay is refused; a forged late voucher is still checked first.
    let err = reordering
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &low, 0)
        .await
        .unwrap_err();
    assert!(err.message.contains("(seen)"), "{}", err.message);
    let err = reordering
        .verify_and_accept_voucher(&channel_id, None, 1_500, None, &low, 0)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidSignature));
}

/// A late voucher draws on the highest voucher's funds, so it need not be
/// above the amount settled on chain; a voucher raising the highest does.
#[tokio::test]
async fn late_vouchers_below_the_settled_amount_are_accepted() {
    let signer = PrivateKeySigner::random();
    let channel_id = format!("0x{}", "cd".repeat(32));
    let id = channel_id.parse::<B256>().unwrap();
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 3_000;
    state.settled_on_chain = 3_000;
    state.spent = 3_000;
    state.deposit = 10_000;
    state.window = Some(VoucherWindow {
        floor: 1_000,
        runs: vec![VoucherRun {
            from: 2_000,
            to: 3_000,
            at: now_ms_for_tests(),
        }],
    });
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state);
    let method = test_session_method(store).with_reorder_window(Duration::from_secs(30));

    let late = signed(&signer, id, 2_000).await;
    method
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &late, 0)
        .await
        .unwrap();
}

fn now_ms_for_tests() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A voucher above the highest one adds funds and is never refused as seen,
/// also when its `after` is behind (a client whose counter is not shared).
#[test]
fn vouchers_above_the_highest_are_never_seen() {
    let state = accept(channel_at(100), 120, Some(100), NOW).unwrap();
    let state = accept(state, 130, Some(100), NOW).unwrap();
    assert_eq!(state.highest_voucher_amount, 130);
    assert_eq!(runs(&state), vec![(100, 130)]);
}

/// A highest voucher raised outside the window, such as by an open,
/// restarts it with every voucher up to the highest below its floor.
#[test]
fn a_highest_voucher_raised_outside_the_window_restarts_it() {
    let mut state = accept(channel_at(100), 120, Some(110), NOW).unwrap();
    state.highest_voucher_amount = 200;
    let err = accept(state.clone(), 110, Some(100), NOW).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
    let state = accept(state, 210, None, NOW).unwrap();
    assert_eq!(state.window.as_ref().unwrap().floor, 200);
    assert_eq!(runs(&state), vec![(200, 210)]);
}

/// The window keeps at most `MAX_VOUCHER_RUNS` runs: past it the lowest
/// move below the floor, which refuses them as stale.
#[test]
fn runs_are_bounded() {
    let count = MAX_VOUCHER_RUNS as u128 + 2;
    let mut state = channel_at(0);
    // Every other unit is left as a hole: no two runs touch.
    for i in 0..count {
        state = accept(state, 2 * i + 2, Some(2 * i + 1), NOW).unwrap();
    }
    let window = state.window.as_ref().unwrap();
    assert_eq!(window.runs.len(), MAX_VOUCHER_RUNS);
    assert_eq!(window.floor, 4);
    let err = accept(state.clone(), 3, Some(2), NOW).unwrap_err();
    assert!(err.message.contains("(stale)"), "{}", err.message);
    assert!(accept(state, 5, Some(4), NOW).is_ok());
}

/// A channel store shared with other server instances: its first `losses`
/// writes find that another instance accepted a voucher (3000 after 2000)
/// since they read, and fail as a lost compare-exchange does.
struct LosesRaces {
    inner: InMemoryChannelStore,
    losses: std::sync::atomic::AtomicUsize,
    writes: std::sync::atomic::AtomicUsize,
}

impl LosesRaces {
    fn new(losses: usize) -> Self {
        Self {
            inner: InMemoryChannelStore::new(),
            losses: losses.into(),
            writes: 0.into(),
        }
    }
}

impl ChannelStore for LosesRaces {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        self.inner.get_channel(channel_id)
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                + Send,
        >,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        use std::sync::atomic::Ordering;

        self.writes.fetch_add(1, Ordering::SeqCst);
        let left = self.losses.load(Ordering::SeqCst);
        if left == 0 {
            return self.inner.update_channel(channel_id, updater);
        }
        self.losses.store(left - 1, Ordering::SeqCst);
        let current = self.inner.get_channel_sync(channel_id).unwrap();
        if current.highest_voucher_amount < 3_000 {
            let other = current
                .accept_voucher_in_window(
                    3_000,
                    Some(2_000),
                    vec![3],
                    0,
                    now_ms_for_tests(),
                    WINDOW_MS,
                )
                .unwrap();
            self.inner.insert(channel_id, other);
        }
        Box::pin(async {
            Err(VerificationError::concurrent_update(
                "channel changed concurrently; retry against fresh state",
            ))
        })
    }
}

/// With a reorder window, a voucher whose store write lost a race against
/// another instance is applied again to the fresh state, a bounded number of
/// times; without one the conflict is returned with its own code.
#[tokio::test]
async fn reorder_window_reapplies_a_voucher_after_a_lost_store_race() {
    use crate::protocol::methods::tempo::session_method::voucher::MAX_VOUCHER_UPDATE_ATTEMPTS;
    use std::sync::atomic::Ordering;

    let signer = PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ef".repeat(32));
    let id = channel_id.parse::<B256>().unwrap();
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    let voucher = signed(&signer, id, 2_000).await;
    let method = |store: Arc<LosesRaces>| {
        SessionMethod::new(
            crate::server::tempo_provider("https://rpc.test.invalid").unwrap(),
            store,
            SessionMethodConfig {
                escrow_contract: "0x5555555555555555555555555555555555555555"
                    .parse()
                    .unwrap(),
                chain_id: 42431,
                min_voucher_delta: 0,
            },
        )
    };

    // Two lost races: both vouchers end up accepted.
    let store = Arc::new(LosesRaces::new(2));
    store.inner.insert(&channel_id, state.clone());
    let accepted = method(store.clone())
        .with_reorder_window(Duration::from_secs(30))
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &voucher, 0)
        .await
        .unwrap();
    assert_eq!(accepted.highest_voucher_amount, 3_000);
    assert_eq!(runs(&accepted), vec![(1_000, 3_000)]);
    assert_eq!(store.writes.load(Ordering::SeqCst), 3);

    // Losing every attempt gives up after the bound with the conflict's code.
    let store = Arc::new(LosesRaces::new(usize::MAX));
    store.inner.insert(&channel_id, state.clone());
    let err = method(store.clone())
        .with_reorder_window(Duration::from_secs(30))
        .verify_and_accept_voucher(&channel_id, None, 2_000, Some(1_000), &voucher, 0)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ConcurrentUpdate));
    assert_eq!(
        store.writes.load(Ordering::SeqCst),
        MAX_VOUCHER_UPDATE_ATTEMPTS
    );

    // Without a window the voucher is not applied again.
    let store = Arc::new(LosesRaces::new(1));
    store.inner.insert(&channel_id, state);
    let err = method(store.clone())
        .verify_and_accept_voucher(&channel_id, None, 2_000, None, &voucher, 0)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ConcurrentUpdate));
    assert_eq!(store.writes.load(Ordering::SeqCst), 1);
}

/// A configured window longer than the maximum is capped at it, and
/// acceptance with it cannot overflow.
#[tokio::test]
async fn unbounded_reorder_window_is_capped() {
    let signer = PrivateKeySigner::random();
    let channel_id = format!("0x{}", "aa".repeat(32));
    let id = channel_id.parse::<B256>().unwrap();
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state);
    let method = test_session_method(store).with_reorder_window(Duration::MAX);
    assert_eq!(
        method.challenge_method_details().unwrap()["reorderWindow"],
        crate::protocol::methods::tempo::session::MAX_REORDER_WINDOW_SECS
    );
    for (cumulative, after) in [(3_000, 2_000), (2_000, 1_000)] {
        let voucher = signed(&signer, id, cumulative).await;
        method
            .verify_and_accept_voucher(&channel_id, None, cumulative, Some(after), &voucher, 0)
            .await
            .unwrap();
    }
    // Pruning with an extreme window and clock saturates.
    let state = channel_at(100);
    let state = state
        .accept_voucher_in_window(120, Some(110), vec![1], 0, u64::MAX, u64::MAX)
        .unwrap();
    assert_eq!(state.highest_voucher_amount, 120);
}
