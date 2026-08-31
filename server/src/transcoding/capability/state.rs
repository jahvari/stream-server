use std::fmt;

use serde::{Deserialize, Serialize};

use crate::transcoding::CapabilityState;

use super::key::{CapabilityKey, PersistedCapabilityKey};

const MINUTE_MS: u64 = 60_000;
const MAX_EVIDENCE_TTL_MS: u64 = 24 * 60 * MINUTE_MS;
const MAX_FUTURE_SKEW_MS: u64 = 5 * MINUTE_MS;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_FAILURE_STREAK: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct EvidenceTimestamp(u64);

impl EvidenceTimestamp {
    pub(super) fn new(milliseconds_since_epoch: u64) -> Result<Self, StateError> {
        if milliseconds_since_epoch > MAX_SAFE_INTEGER {
            return Err(StateError::Bounds);
        }
        Ok(Self(milliseconds_since_epoch))
    }

    fn checked_add(self, milliseconds: u64) -> Result<Self, StateError> {
        Self::new(self.0.checked_add(milliseconds).ok_or(StateError::Bounds)?)
    }

    pub(super) const fn milliseconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StateNow {
    wall: EvidenceTimestamp,
    monotonic_ms: u64,
}

impl StateNow {
    pub(super) fn new(wall: EvidenceTimestamp, monotonic_ms: u64) -> Result<Self, StateError> {
        if monotonic_ms > MAX_SAFE_INTEGER {
            return Err(StateError::Bounds);
        }
        Ok(Self { wall, monotonic_ms })
    }

    pub(super) const fn wall(self) -> EvidenceTimestamp {
        self.wall
    }

    pub(super) const fn monotonic_milliseconds(self) -> u64 {
        self.monotonic_ms
    }

    #[cfg(test)]
    pub(super) fn from_test_minutes(minutes: u64) -> Self {
        Self::from_test_times(minutes, minutes)
    }

    #[cfg(test)]
    pub(super) fn from_test_times(wall_minutes: u64, monotonic_minutes: u64) -> Self {
        let wall_ms = wall_minutes.checked_mul(MINUTE_MS).unwrap();
        let monotonic_ms = monotonic_minutes.checked_mul(MINUTE_MS).unwrap();
        Self::new(EvidenceTimestamp::new(wall_ms).unwrap(), monotonic_ms).unwrap()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum EvidenceTarget {
    Correctness,
    Realtime,
    Segmented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum EvidenceOutcome {
    CorrectnessPassed,
    RealtimePassed,
    Unsupported,
    NotPresent,
    TemporaryFailure,
    PermanentFailure,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum EvidenceReason {
    VerificationFailed,
    VerificationNotImplemented,
    VerificationTimeout,
    Unsupported,
    PermanentFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VerifierMode {
    ObservationalOnly,
    ActiveInjected,
}

#[cfg(test)]
pub(super) type VerificationMode = VerifierMode;

#[cfg(test)]
impl VerifierMode {
    #[allow(non_upper_case_globals)]
    pub(super) const Active: Self = Self::ActiveInjected;
    #[allow(non_upper_case_globals)]
    pub(super) const Unknown: Self = Self::ObservationalOnly;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerificationResult {
    target: EvidenceTarget,
    outcome: EvidenceOutcome,
    reason: Option<EvidenceReason>,
    observed_at: EvidenceTimestamp,
    duration_ms: u64,
    expires_at: EvidenceTimestamp,
}

impl VerificationResult {
    pub(super) fn new(
        target: EvidenceTarget,
        outcome: EvidenceOutcome,
        reason: Option<EvidenceReason>,
        observed_at: EvidenceTimestamp,
        duration_ms: u64,
        expires_at: EvidenceTimestamp,
    ) -> Result<Self, StateError> {
        let result = Self {
            target,
            outcome,
            reason,
            observed_at,
            duration_ms,
            expires_at,
        };
        result.validate_shape()?;
        Ok(result)
    }

    fn validate_shape(self) -> Result<(), StateError> {
        if self.duration_ms > MAX_SAFE_INTEGER
            || self.expires_at <= self.observed_at
            || self.expires_at.0 - self.observed_at.0 > MAX_EVIDENCE_TTL_MS
        {
            return Err(StateError::Bounds);
        }
        let positive = matches!(
            self.outcome,
            EvidenceOutcome::CorrectnessPassed | EvidenceOutcome::RealtimePassed
        );
        if positive == self.reason.is_some() {
            return Err(StateError::InvalidResult);
        }
        match (self.outcome, self.reason) {
            (EvidenceOutcome::Unsupported, Some(EvidenceReason::Unsupported))
            | (EvidenceOutcome::PermanentFailure, Some(EvidenceReason::PermanentFailure))
            | (
                EvidenceOutcome::TemporaryFailure,
                Some(EvidenceReason::VerificationFailed | EvidenceReason::VerificationTimeout),
            )
            | (EvidenceOutcome::NotPresent | EvidenceOutcome::Cancelled, Some(_))
            | (EvidenceOutcome::CorrectnessPassed | EvidenceOutcome::RealtimePassed, None) => {}
            _ => return Err(StateError::InvalidResult),
        }
        match (self.target, self.outcome) {
            (
                EvidenceTarget::Correctness | EvidenceTarget::Segmented,
                EvidenceOutcome::CorrectnessPassed,
            )
            | (EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed)
            | (_, EvidenceOutcome::Unsupported)
            | (_, EvidenceOutcome::NotPresent)
            | (_, EvidenceOutcome::TemporaryFailure)
            | (_, EvidenceOutcome::PermanentFailure)
            | (_, EvidenceOutcome::Cancelled) => Ok(()),
            _ => Err(StateError::InvalidResult),
        }
    }

    fn validate_at(self, now: StateNow) -> Result<(), StateError> {
        self.validate_shape()?;
        if self.observed_at.0 > now.wall.0.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(StateError::FutureObservation);
        }
        if self.expires_at <= now.wall {
            return Err(StateError::ExpiredResult);
        }
        Ok(())
    }

    pub(super) const fn outcome(self) -> EvidenceOutcome {
        self.outcome
    }

    pub(super) const fn target(self) -> EvidenceTarget {
        self.target
    }

    #[cfg(test)]
    pub(super) fn for_test(
        target: EvidenceTarget,
        outcome: EvidenceOutcome,
        reason: EvidenceReason,
        minute: u64,
    ) -> Self {
        let observed_at = EvidenceTimestamp::new(minute * MINUTE_MS).unwrap();
        let positive = matches!(
            outcome,
            EvidenceOutcome::CorrectnessPassed | EvidenceOutcome::RealtimePassed
        );
        Self::new(
            target,
            outcome,
            (!positive).then_some(reason),
            observed_at,
            100,
            observed_at.checked_add(MAX_EVIDENCE_TTL_MS).unwrap(),
        )
        .unwrap()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EvidenceObservation {
    pub(super) target: EvidenceTarget,
    pub(super) outcome: EvidenceOutcome,
    pub(super) observed_at: EvidenceTimestamp,
    pub(super) duration_ms: u64,
    pub(super) expires_at: EvidenceTimestamp,
    monotonic_expires_at_ms: u64,
}

impl EvidenceObservation {
    fn from_result(result: VerificationResult, now: StateNow) -> Result<Self, StateError> {
        Ok(Self {
            target: result.target,
            outcome: result.outcome,
            observed_at: result.observed_at,
            duration_ms: result.duration_ms,
            expires_at: result.expires_at,
            monotonic_expires_at_ms: monotonic_deadline(result.expires_at, now)?,
        })
    }

    fn is_current(&self, now: StateNow) -> bool {
        now.wall < self.expires_at && now.monotonic_ms < self.monotonic_expires_at_ms
    }

    fn validate_as(
        &self,
        target: EvidenceTarget,
        outcome: EvidenceOutcome,
        now: StateNow,
    ) -> Result<(), StateError> {
        if self.target != target
            || self.outcome != outcome
            || self.duration_ms > MAX_SAFE_INTEGER
            || self.expires_at <= self.observed_at
            || self.expires_at.0 - self.observed_at.0 > MAX_EVIDENCE_TTL_MS
            || !self.is_current(now)
        {
            return Err(StateError::ImpossibleState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TerminalObservation {
    pub(super) target: EvidenceTarget,
    pub(super) outcome: EvidenceOutcome,
    pub(super) reason: EvidenceReason,
    pub(super) observed_at: EvidenceTimestamp,
    pub(super) duration_ms: u64,
    pub(super) expires_at: EvidenceTimestamp,
    monotonic_expires_at_ms: u64,
}

impl TerminalObservation {
    fn from_result(result: VerificationResult, now: StateNow) -> Result<Self, StateError> {
        if !matches!(
            result.outcome,
            EvidenceOutcome::Unsupported | EvidenceOutcome::PermanentFailure
        ) {
            return Err(StateError::InvalidResult);
        }
        Ok(Self {
            target: result.target,
            outcome: result.outcome,
            reason: result.reason.ok_or(StateError::InvalidResult)?,
            observed_at: result.observed_at,
            duration_ms: result.duration_ms,
            expires_at: result.expires_at,
            monotonic_expires_at_ms: monotonic_deadline(result.expires_at, now)?,
        })
    }

    fn is_current(&self, now: StateNow) -> bool {
        now.wall < self.expires_at && now.monotonic_ms < self.monotonic_expires_at_ms
    }

    fn validate(&self, now: StateNow) -> Result<(), StateError> {
        let reason_matches = matches!(
            (self.outcome, self.reason),
            (EvidenceOutcome::Unsupported, EvidenceReason::Unsupported)
                | (
                    EvidenceOutcome::PermanentFailure,
                    EvidenceReason::PermanentFailure
                )
        );
        if !reason_matches
            || self.duration_ms > MAX_SAFE_INTEGER
            || self.expires_at <= self.observed_at
            || self.expires_at.0 - self.observed_at.0 > MAX_EVIDENCE_TTL_MS
            || !self.is_current(now)
        {
            return Err(StateError::ImpossibleState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FailureHistory {
    pub(super) streak: u8,
    pub(super) last_failure_at: EvidenceTimestamp,
    pub(super) expires_at: EvidenceTimestamp,
    pub(super) cooldown_until: Option<EvidenceTimestamp>,
    monotonic_cooldown_until_ms: Option<u64>,
    monotonic_expires_at_ms: u64,
}

impl FailureHistory {
    fn next(
        previous: Option<&Self>,
        observed_at: EvidenceTimestamp,
        now: StateNow,
    ) -> Result<Self, StateError> {
        let previous_streak = previous
            .filter(|history| now.wall < history.expires_at)
            .map_or(0, |history| history.streak);
        let streak = previous_streak.saturating_add(1).min(MAX_FAILURE_STREAK);
        let cooldown_ms = cooldown_for_streak(streak);
        let cooldown_until = observed_at.checked_add(cooldown_ms)?;
        let remaining_ms = cooldown_until.0.saturating_sub(now.wall.0).min(cooldown_ms);
        Ok(Self {
            streak,
            last_failure_at: observed_at,
            expires_at: observed_at.checked_add(MAX_EVIDENCE_TTL_MS)?,
            cooldown_until: Some(cooldown_until),
            monotonic_cooldown_until_ms: Some(
                now.monotonic_ms
                    .checked_add(remaining_ms)
                    .ok_or(StateError::Bounds)?,
            ),
            monotonic_expires_at_ms: now
                .monotonic_ms
                .checked_add(
                    observed_at
                        .checked_add(MAX_EVIDENCE_TTL_MS)?
                        .0
                        .saturating_sub(now.wall.0)
                        .min(MAX_EVIDENCE_TTL_MS),
                )
                .ok_or(StateError::Bounds)?,
        })
    }

    fn is_current(&self, now: StateNow) -> bool {
        now.wall < self.expires_at && now.monotonic_ms < self.monotonic_expires_at_ms
    }

    fn circuit_is_open(&self, now: StateNow) -> bool {
        self.cooldown_until.is_some()
            && self
                .monotonic_cooldown_until_ms
                .is_some_and(|deadline| now.monotonic_ms < deadline)
    }
}

fn monotonic_deadline(expires_at: EvidenceTimestamp, now: StateNow) -> Result<u64, StateError> {
    now.monotonic_ms
        .checked_add(
            expires_at
                .0
                .saturating_sub(now.wall.0)
                .min(MAX_EVIDENCE_TTL_MS),
        )
        .ok_or(StateError::Bounds)
}

const fn cooldown_for_streak(streak: u8) -> u64 {
    match streak {
        0 | 1 => 10 * MINUTE_MS,
        2 => 20 * MINUTE_MS,
        3 => 40 * MINUTE_MS,
        _ => 60 * MINUTE_MS,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProjectionContext {
    administratively_disabled: bool,
    listed: bool,
}

impl ProjectionContext {
    pub(super) const fn new(administratively_disabled: bool, listed: bool) -> Self {
        Self {
            administratively_disabled,
            listed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkState {
    Absent,
    Queued,
    Verifying,
}

impl WorkState {
    pub(super) const fn external_state(self) -> Option<CapabilityState> {
        let _ = self;
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Transition {
    NoChange,
    KeepRecord,
    RemoveRecord,
}

impl Transition {
    pub(super) const fn remove_record(self) -> bool {
        matches!(self, Self::RemoveRecord)
    }

    pub(super) const fn changes_record(self) -> bool {
        !matches!(self, Self::NoChange)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EvidenceRecord {
    pub(super) key: CapabilityKey,
    pub(super) correctness: Option<EvidenceObservation>,
    pub(super) realtime: Option<EvidenceObservation>,
    pub(super) segmented: Option<EvidenceObservation>,
    pub(super) terminal: Option<TerminalObservation>,
    pub(super) failure_history: Option<FailureHistory>,
}

impl EvidenceRecord {
    pub(super) fn new(key: CapabilityKey) -> Self {
        Self {
            key,
            correctness: None,
            realtime: None,
            segmented: None,
            terminal: None,
            failure_history: None,
        }
    }

    pub(super) fn apply(
        &mut self,
        result: VerificationResult,
        mode: VerifierMode,
        now: StateNow,
    ) -> Result<Transition, StateError> {
        result.validate_at(now)?;
        if mode == VerifierMode::ObservationalOnly {
            return if result.outcome == EvidenceOutcome::NotPresent
                && result.reason == Some(EvidenceReason::VerificationNotImplemented)
            {
                Ok(Transition::NoChange)
            } else {
                Err(StateError::InvalidVerifierMode)
            };
        }
        self.prune_expired(now);

        match result.outcome {
            EvidenceOutcome::CorrectnessPassed if result.target == EvidenceTarget::Correctness => {
                self.correctness = Some(EvidenceObservation::from_result(result, now)?);
                self.terminal = None;
                self.failure_history = None;
            }
            EvidenceOutcome::CorrectnessPassed if result.target == EvidenceTarget::Segmented => {
                self.require_current_correctness(now)?;
                self.segmented = Some(EvidenceObservation::from_result(result, now)?);
                self.failure_history = None;
            }
            EvidenceOutcome::RealtimePassed if result.target == EvidenceTarget::Realtime => {
                self.require_current_correctness(now)?;
                self.realtime = Some(EvidenceObservation::from_result(result, now)?);
                self.failure_history = None;
            }
            EvidenceOutcome::Unsupported | EvidenceOutcome::PermanentFailure => {
                self.correctness = None;
                self.realtime = None;
                self.segmented = None;
                self.failure_history = None;
                self.terminal = Some(TerminalObservation::from_result(result, now)?);
            }
            EvidenceOutcome::TemporaryFailure => {
                self.failure_history = Some(FailureHistory::next(
                    self.failure_history.as_ref(),
                    result.observed_at,
                    now,
                )?);
            }
            EvidenceOutcome::NotPresent => return Ok(Transition::RemoveRecord),
            EvidenceOutcome::Cancelled => return Ok(Transition::NoChange),
            EvidenceOutcome::CorrectnessPassed | EvidenceOutcome::RealtimePassed => {
                return Err(StateError::InvalidResult);
            }
        }
        self.validate(now)?;
        Ok(Transition::KeepRecord)
    }

    pub(super) fn project(
        &mut self,
        now: StateNow,
        context: ProjectionContext,
    ) -> Option<CapabilityState> {
        self.prune_expired(now);
        let visible = context.listed
            || self.correctness.is_some()
            || self.realtime.is_some()
            || self.segmented.is_some()
            || self.terminal.is_some()
            || self
                .failure_history
                .as_ref()
                .is_some_and(|history| history.circuit_is_open(now));
        if !visible {
            return None;
        }
        if context.administratively_disabled {
            return Some(CapabilityState::AdministrativelyDisabled);
        }
        if self
            .failure_history
            .as_ref()
            .is_some_and(|history| history.circuit_is_open(now))
        {
            return Some(CapabilityState::CircuitOpen);
        }
        if self.terminal.is_some() {
            return Some(CapabilityState::Failed);
        }
        if self.realtime.is_some() {
            return Some(CapabilityState::RealtimeQualified);
        }
        if self.correctness.is_some() || self.segmented.is_some() {
            return Some(CapabilityState::CorrectnessVerified);
        }
        context.listed.then_some(CapabilityState::Listed)
    }

    pub(super) fn clear_cooldown_after_refresh(&mut self, now: StateNow) {
        self.prune_expired(now);
        if let Some(history) = &mut self.failure_history {
            history.cooldown_until = None;
            history.monotonic_cooldown_until_ms = None;
        }
    }

    pub(super) fn prune_expired(&mut self, now: StateNow) {
        if self
            .correctness
            .as_ref()
            .is_some_and(|observation| !observation.is_current(now))
        {
            self.correctness = None;
            self.realtime = None;
            self.segmented = None;
        } else {
            if self
                .realtime
                .as_ref()
                .is_some_and(|observation| !observation.is_current(now))
            {
                self.realtime = None;
            }
            if self
                .segmented
                .as_ref()
                .is_some_and(|observation| !observation.is_current(now))
            {
                self.segmented = None;
            }
        }
        if self
            .terminal
            .as_ref()
            .is_some_and(|observation| !observation.is_current(now))
        {
            self.terminal = None;
        }
        if self
            .failure_history
            .as_ref()
            .is_some_and(|history| !history.is_current(now))
        {
            self.failure_history = None;
        }
    }

    pub(super) fn validate(&self, now: StateNow) -> Result<(), StateError> {
        if let Some(observation) = &self.correctness {
            observation.validate_as(
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
                now,
            )?;
        }
        if let Some(observation) = &self.realtime {
            observation.validate_as(
                EvidenceTarget::Realtime,
                EvidenceOutcome::RealtimePassed,
                now,
            )?;
        }
        if let Some(observation) = &self.segmented {
            observation.validate_as(
                EvidenceTarget::Segmented,
                EvidenceOutcome::CorrectnessPassed,
                now,
            )?;
        }
        if let Some(terminal) = &self.terminal {
            terminal.validate(now)?;
        }
        if self.terminal.is_some()
            && (self.correctness.is_some() || self.realtime.is_some() || self.segmented.is_some())
        {
            return Err(StateError::ImpossibleState);
        }
        if (self.realtime.is_some() || self.segmented.is_some())
            && self.require_current_correctness(now).is_err()
        {
            return Err(StateError::ImpossibleState);
        }
        if let Some(history) = &self.failure_history
            && (history.streak == 0
                || history.streak > MAX_FAILURE_STREAK
                || history.expires_at <= history.last_failure_at
                || history.expires_at.0 - history.last_failure_at.0 > MAX_EVIDENCE_TTL_MS
                || history.cooldown_until.is_some()
                    != history.monotonic_cooldown_until_ms.is_some()
                || history.monotonic_expires_at_ms <= now.monotonic_ms
                || history.cooldown_until.is_some_and(|cooldown| {
                    cooldown <= history.last_failure_at
                        || cooldown.0 - history.last_failure_at.0 > 60 * MINUTE_MS
                }))
        {
            return Err(StateError::ImpossibleState);
        }
        Ok(())
    }

    fn require_current_correctness(&self, now: StateNow) -> Result<(), StateError> {
        if self
            .correctness
            .as_ref()
            .is_some_and(|observation| observation.is_current(now))
        {
            Ok(())
        } else {
            Err(StateError::MissingCorrectness)
        }
    }

    pub(super) fn last_observed_at(&self) -> Option<EvidenceTimestamp> {
        [
            self.correctness.as_ref().map(|item| item.observed_at),
            self.realtime.as_ref().map(|item| item.observed_at),
            self.segmented.as_ref().map(|item| item.observed_at),
            self.terminal.as_ref().map(|item| item.observed_at),
            self.failure_history
                .as_ref()
                .map(|item| item.last_failure_at),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    pub(super) fn target_is_current(&self, target: EvidenceTarget, now: StateNow) -> bool {
        match target {
            EvidenceTarget::Correctness => self
                .correctness
                .as_ref()
                .is_some_and(|observation| observation.is_current(now)),
            EvidenceTarget::Realtime => self
                .realtime
                .as_ref()
                .is_some_and(|observation| observation.is_current(now)),
            EvidenceTarget::Segmented => self
                .segmented
                .as_ref()
                .is_some_and(|observation| observation.is_current(now)),
        }
    }

    #[cfg(test)]
    pub(super) fn failure_streak_for_test(&self) -> Option<u8> {
        self.failure_history.as_ref().map(|history| history.streak)
    }

    #[cfg(test)]
    pub(super) fn cooldown_minutes_for_test(&self, now: StateNow) -> Option<u64> {
        self.failure_history
            .as_ref()?
            .monotonic_cooldown_until_ms
            .and_then(|deadline| deadline.checked_sub(now.monotonic_ms))
            .map(|milliseconds| milliseconds / MINUTE_MS)
    }

    #[cfg(test)]
    pub(super) fn has_positive_observations_for_test(&self) -> bool {
        self.correctness.is_some() || self.realtime.is_some() || self.segmented.is_some()
    }

    #[cfg(test)]
    pub(super) fn impossible_for_test() -> Result<(), StateError> {
        let mut record = Self::new(CapabilityKey::complete_test_keys().remove(0));
        record.realtime = Some(EvidenceObservation {
            target: EvidenceTarget::Realtime,
            outcome: EvidenceOutcome::RealtimePassed,
            observed_at: EvidenceTimestamp::new(0)?,
            duration_ms: 1,
            expires_at: EvidenceTimestamp::new(MAX_EVIDENCE_TTL_MS)?,
            monotonic_expires_at_ms: MAX_EVIDENCE_TTL_MS,
        });
        record.validate(StateNow::from_test_minutes(0))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PersistedEvidenceRecord {
    pub(super) key: PersistedCapabilityKey,
    correctness: Option<PersistedObservation>,
    realtime: Option<PersistedObservation>,
    segmented: Option<PersistedObservation>,
    terminal: Option<PersistedTerminalObservation>,
    failure_history: Option<PersistedFailureHistory>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedObservation {
    target: EvidenceTarget,
    outcome: EvidenceOutcome,
    observed_at: u64,
    duration_ms: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedTerminalObservation {
    target: EvidenceTarget,
    outcome: EvidenceOutcome,
    reason: EvidenceReason,
    observed_at: u64,
    duration_ms: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedFailureHistory {
    streak: u8,
    last_failure_at: u64,
    expires_at: u64,
    cooldown_until: Option<u64>,
}

impl PersistedEvidenceRecord {
    pub(super) fn from_record(record: &EvidenceRecord) -> Option<Self> {
        let persisted = Self {
            key: PersistedCapabilityKey::from_key(&record.key)?,
            correctness: record.correctness.as_ref().map(PersistedObservation::from),
            realtime: record.realtime.as_ref().map(PersistedObservation::from),
            segmented: record.segmented.as_ref().map(PersistedObservation::from),
            terminal: record
                .terminal
                .as_ref()
                .map(PersistedTerminalObservation::from),
            failure_history: record
                .failure_history
                .as_ref()
                .map(PersistedFailureHistory::from),
        };
        if persisted.correctness.is_none()
            && persisted.realtime.is_none()
            && persisted.segmented.is_none()
            && persisted.terminal.is_none()
            && persisted.failure_history.is_none()
        {
            None
        } else {
            Some(persisted)
        }
    }

    pub(super) fn into_record(self, now: StateNow) -> Result<EvidenceRecord, StateError> {
        let key = self
            .key
            .into_key()
            .map_err(|_| StateError::ImpossibleState)?;
        if self.correctness.is_none()
            && self.realtime.is_none()
            && self.segmented.is_none()
            && self.terminal.is_none()
            && self.failure_history.is_none()
        {
            return Err(StateError::ImpossibleState);
        }
        let record = EvidenceRecord {
            key,
            correctness: self
                .correctness
                .map(|observation| observation.into_observation(now))
                .transpose()?,
            realtime: self
                .realtime
                .map(|observation| observation.into_observation(now))
                .transpose()?,
            segmented: self
                .segmented
                .map(|observation| observation.into_observation(now))
                .transpose()?,
            terminal: self
                .terminal
                .map(|observation| observation.into_terminal(now))
                .transpose()?,
            failure_history: self
                .failure_history
                .map(|history| history.into_history(now))
                .transpose()?,
        };
        record.validate(now)?;
        Ok(record)
    }
}

impl From<&EvidenceObservation> for PersistedObservation {
    fn from(observation: &EvidenceObservation) -> Self {
        Self {
            target: observation.target,
            outcome: observation.outcome,
            observed_at: observation.observed_at.0,
            duration_ms: observation.duration_ms,
            expires_at: observation.expires_at.0,
        }
    }
}

impl PersistedObservation {
    fn into_observation(self, now: StateNow) -> Result<EvidenceObservation, StateError> {
        let result = VerificationResult::new(
            self.target,
            self.outcome,
            None,
            EvidenceTimestamp::new(self.observed_at)?,
            self.duration_ms,
            EvidenceTimestamp::new(self.expires_at)?,
        )?;
        result.validate_at(now)?;
        EvidenceObservation::from_result(result, now)
    }
}

impl From<&TerminalObservation> for PersistedTerminalObservation {
    fn from(observation: &TerminalObservation) -> Self {
        Self {
            target: observation.target,
            outcome: observation.outcome,
            reason: observation.reason,
            observed_at: observation.observed_at.0,
            duration_ms: observation.duration_ms,
            expires_at: observation.expires_at.0,
        }
    }
}

impl PersistedTerminalObservation {
    fn into_terminal(self, now: StateNow) -> Result<TerminalObservation, StateError> {
        let result = VerificationResult::new(
            self.target,
            self.outcome,
            Some(self.reason),
            EvidenceTimestamp::new(self.observed_at)?,
            self.duration_ms,
            EvidenceTimestamp::new(self.expires_at)?,
        )?;
        result.validate_at(now)?;
        TerminalObservation::from_result(result, now)
    }
}

impl From<&FailureHistory> for PersistedFailureHistory {
    fn from(history: &FailureHistory) -> Self {
        Self {
            streak: history.streak,
            last_failure_at: history.last_failure_at.0,
            expires_at: history.expires_at.0,
            cooldown_until: history.cooldown_until.map(|timestamp| timestamp.0),
        }
    }
}

impl PersistedFailureHistory {
    fn into_history(self, now: StateNow) -> Result<FailureHistory, StateError> {
        let last_failure_at = EvidenceTimestamp::new(self.last_failure_at)?;
        let expires_at = EvidenceTimestamp::new(self.expires_at)?;
        let cooldown_until = self
            .cooldown_until
            .map(EvidenceTimestamp::new)
            .transpose()?;
        if self.streak == 0
            || self.streak > MAX_FAILURE_STREAK
            || last_failure_at.0 > now.wall.0.saturating_add(MAX_FUTURE_SKEW_MS)
            || expires_at <= now.wall
            || expires_at <= last_failure_at
            || expires_at.0 - last_failure_at.0 > MAX_EVIDENCE_TTL_MS
            || cooldown_until.is_some_and(|cooldown| {
                cooldown <= last_failure_at || cooldown.0 - last_failure_at.0 > 60 * MINUTE_MS
            })
        {
            return Err(StateError::ImpossibleState);
        }
        let remaining_expiry = expires_at
            .0
            .saturating_sub(now.wall.0)
            .min(MAX_EVIDENCE_TTL_MS);
        let monotonic_expires_at_ms = now
            .monotonic_ms
            .checked_add(remaining_expiry)
            .ok_or(StateError::Bounds)?;
        let monotonic_cooldown_until_ms = match cooldown_until {
            Some(cooldown) => Some(
                now.monotonic_ms
                    .checked_add(cooldown.0.saturating_sub(now.wall.0).min(60 * MINUTE_MS))
                    .ok_or(StateError::Bounds)?,
            ),
            None => None,
        };
        Ok(FailureHistory {
            streak: self.streak,
            last_failure_at,
            expires_at,
            cooldown_until,
            monotonic_cooldown_until_ms,
            monotonic_expires_at_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StateError {
    Bounds,
    FutureObservation,
    ExpiredResult,
    ImpossibleState,
    InvalidResult,
    InvalidVerifierMode,
    MissingCorrectness,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid capability evidence state")
    }
}

impl std::error::Error for StateError {}
