//! Progress reporting, and the rule about where it may and may not be shown.
//!
//! # Why this is not simply "add a progress bar everywhere"
//!
//! A progress indicator is an output channel like any other, and this program
//! has one subcommand whose entire design is about what it refuses to output.
//! The three are therefore treated differently, and the difference is not a
//! matter of taste:
//!
//! - **`scan`** reads files the user already has and reports on them. Every
//!   figure a progress bar could show — how many images, how large, how far
//!   along — is either public or already in the report it prints at the end.
//!   Full progress, with a time estimate.
//!
//! - **`embed`** would be allowed to report its stages: the work it does is a
//!   function of the container's size and the payload's length, and both are
//!   printed in the report at the end anyway, so naming a stage would reveal
//!   nothing the finished output does not. It gets [`Activity`] all the same,
//!   for a reason that is not about secrecy — `EmbedPipeline::embed` is one
//!   opaque call with no point at which it reports having got anywhere. A
//!   determinate bar would mean threading a callback through four layers of the
//!   core, and a bar that guessed instead would be inventing the one number the
//!   user would actually rely on.
//!
//! - **`extract`** may not. Its failures are deliberately indistinguishable: a
//!   wrong password, an image carrying nothing and a damaged payload all print
//!   one sentence, because telling them apart is exactly the question an
//!   attacker holding an intercepted image is asking. A staged indicator would
//!   answer it visually — a run that reached "decrypting the payload" before
//!   failing has announced that a plausible length header decoded, which is to
//!   say that the password was probably right. The same applies to the second
//!   salt hypothesis: showing that a second attempt started reveals that the
//!   first one failed.
//!
//!   So the extraction path gets [`Activity`], which says only that the process
//!   is alive. It carries one fixed label, it never names a stage, and it is
//!   identical in success and in failure.
//!
//! # What this does not claim to fix
//!
//! Extraction already takes about twice as long when it has to try the second
//! salt hypothesis, and no choice made here changes that. That is a timing
//! side channel, it predates this module, and it is outside the threat model
//! the project states: the assumed adversary holds the intercepted image, not a
//! stopwatch pointed at your terminal. The rule above is about not *adding* a
//! channel that is far easier to read than a stopwatch.

use std::io::IsTerminal;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// How often the spinner redraws itself.
const TICK_INTERVAL: Duration = Duration::from_millis(120);

/// The one thing the extraction path is allowed to say while it works.
///
/// Deliberately says nothing about what it is doing. See the module
/// documentation.
const WORKING_LABEL: &str = "Working";

/// Whether progress may be drawn at all.
///
/// Standard error rather than standard output: `scan --json` writes a document
/// to stdout and `extract` writes raw payload bytes to it, and neither may have
/// a progress bar spliced into it. Drawing only when stderr is a terminal is
/// also what keeps a redirected log free of cursor escapes.
fn can_draw() -> bool {
    std::io::stderr().is_terminal()
}

/// Assembles the determinate bar.
///
/// The template names a percentage, the file in hand and a time estimate,
/// because "how much longer" is the question the bar exists to answer. A
/// malformed template falls back to the default rather than failing: progress
/// reporting is a convenience, and no failure of it is a reason to refuse to do
/// the work the user asked for.
fn build_bar(
    title: &str,
    total: u64,
    target: ProgressDrawTarget,
    steady_tick: bool,
) -> ProgressBar {
    let bar = ProgressBar::with_draw_target(Some(total.max(1)), target);

    if let Ok(style) =
        ProgressStyle::with_template("  {msg}\n  [{bar:32}] {percent:>3}%  {prefix}  ETA {eta}")
    {
        bar.set_style(style.progress_chars("=> "));
    }

    bar.set_message(title.to_owned());

    // The steady tick is what keeps the estimate moving while a single large
    // container is being analysed, which on a hundred-megapixel export is
    // several seconds spent inside one file. Without it the bar would freeze
    // exactly when the user most wants to know the process is still alive.
    //
    // It also takes over drawing: with a ticker running, `inc` no longer
    // redraws synchronously. That is invisible in a real run and fatal to a
    // test that advances and reads the terminal in the next statement, which is
    // why the tests build the bar without one.
    if steady_tick {
        bar.enable_steady_tick(TICK_INTERVAL);
    }

    bar
}

/// A determinate progress bar over a known amount of work.
///
/// The unit is deliberately not "files". See [`Progress::new`].
pub struct Progress {
    /// `None` when nothing may be drawn, which makes every method a no-op.
    bar: Option<ProgressBar>,
}

impl Progress {
    /// Starts a bar over `total` units of work, labelled `title`.
    ///
    /// # Why the unit is megapixels and not files
    ///
    /// Every estimate a progress bar makes rests on the assumption that the
    /// remaining items cost about what the finished ones did. Counting files
    /// breaks that assumption badly here: the analysis is proportional to pixel
    /// count, and a folder of photographs mixes four-megapixel snapshots with
    /// hundred-megapixel exports. A bar counting files would sit at 90% and
    /// then take longer than the first 90% did, which is worse than showing
    /// nothing — it is a prediction the user will act on and it is wrong.
    ///
    /// Measuring the work in megapixels makes the estimate honest, because the
    /// figure it divides by is the one the cost is actually proportional to.
    pub fn new(title: &str, total: u64) -> Self {
        if !can_draw() {
            return Self { bar: None };
        }

        Self {
            bar: Some(build_bar(title, total, ProgressDrawTarget::stderr(), true)),
        }
    }

    /// The same bar, drawn wherever the caller says.
    ///
    /// Exists so the rendering can be asserted against an in-memory terminal;
    /// see the tests. [`Progress::new`] is the only constructor the program
    /// itself uses.
    #[cfg(test)]
    fn to_target(title: &str, total: u64, target: ProgressDrawTarget) -> Self {
        Self {
            bar: Some(build_bar(title, total, target, false)),
        }
    }

    /// Names what is being worked on right now.
    pub fn set_detail(&self, detail: &str) {
        if let Some(bar) = &self.bar {
            bar.set_prefix(detail.to_owned());
        }
    }

    /// Records `units` of work as finished.
    pub fn advance(&self, units: u64) {
        if let Some(bar) = &self.bar {
            bar.inc(units);
        }
    }

    /// Redraws now rather than at the next tick.
    ///
    /// Only the tests need this. In a real run the steady tick redraws several
    /// times a second, and indicatif deliberately rate-limits redraws so that a
    /// fast loop does not spend its time writing escape sequences — which is
    /// also why a test that advances and immediately reads the terminal would
    /// otherwise see the frame before the advance.
    #[cfg(test)]
    fn redraw(&self) {
        if let Some(bar) = &self.bar {
            bar.tick();
        }
    }

    /// Clears the bar, leaving the terminal as it was found.
    ///
    /// The report that follows is the output that matters, and a finished
    /// progress bar left above it is noise in anything the user pastes
    /// elsewhere.
    pub fn finish(self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

/// An indeterminate indicator that reveals nothing but that work is happening.
///
/// The only form of progress the extraction path may use. It has no stages, no
/// count and no estimate, and it reads identically whether the run is about to
/// succeed or about to fail — which is the property that whole path is built
/// around. See the module documentation.
pub struct Activity {
    /// `None` when nothing may be drawn, which makes every method a no-op.
    bar: Option<ProgressBar>,
}

impl Activity {
    /// Starts the indicator.
    pub fn start() -> Self {
        if !can_draw() {
            return Self { bar: None };
        }

        let bar = ProgressBar::new_spinner();
        if let Ok(style) = ProgressStyle::with_template("  {spinner} {msg}") {
            bar.set_style(style);
        }

        // One fixed label, set once. There is deliberately no method to change
        // it: a stage name is exactly what this type exists not to reveal.
        bar.set_message(WORKING_LABEL);
        bar.enable_steady_tick(TICK_INTERVAL);

        Self { bar: Some(bar) }
    }

    /// Stops the indicator and clears it.
    ///
    /// Takes no argument on purpose. A "finished successfully" and a "finished
    /// in failure" that looked different would reintroduce, in the last frame
    /// drawn, the distinction the caller spends its whole error path hiding.
    pub fn finish(self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The indicators are inert when there is no terminal to draw on.
    ///
    /// Which is the case under `cargo test`, so this also pins that the suite
    /// is not quietly writing escape sequences into its own output.
    #[test]
    fn nothing_is_drawn_without_a_terminal() {
        assert!(!can_draw(), "the test harness must not hold a terminal");

        let progress = Progress::new("scanning", 100);
        assert!(progress.bar.is_none());
        // Every method has to stay callable, because the caller does not check.
        progress.set_detail("a file");
        progress.advance(10);
        progress.finish();

        let activity = Activity::start();
        assert!(activity.bar.is_none());
        activity.finish();
    }

    /// The bar draws a percentage, the file in hand and an estimate.
    ///
    /// Asserted against an in-memory terminal rather than trusted: the point of
    /// the whole exercise is that the user sees how much longer the scan has to
    /// run, and a template that silently failed to build would leave a bar that
    /// draws none of it.
    #[test]
    fn the_bar_draws_what_the_user_came_for() {
        let terminal = indicatif::InMemoryTerm::new(6, 90);
        let progress = Progress::to_target(
            "Analysing 3 of 40 files",
            100,
            // A refresh rate high enough that a redraw is never withheld.
            // indicatif rate-limits drawing so a fast loop does not spend its
            // time writing escape sequences, which in a test that advances and
            // reads immediately would show the frame before the advance.
            ProgressDrawTarget::term_like_with_hz(Box::new(terminal.clone()), 255),
        );

        progress.set_detail("holiday.png");
        progress.advance(25);
        progress.redraw();

        let drawn = terminal.contents();
        assert!(drawn.contains("Analysing 3 of 40 files"), "got: {drawn}");
        assert!(drawn.contains("holiday.png"), "got: {drawn}");
        assert!(drawn.contains("25%"), "got: {drawn}");
        assert!(drawn.contains("ETA"), "got: {drawn}");

        // Cleared afterwards, so the report that follows is not preceded by a
        // finished bar nobody needs to read.
        progress.finish();
        assert!(
            terminal.contents().is_empty(),
            "got: {}",
            terminal.contents()
        );
    }

    /// Work is measured in the unit the cost is proportional to.
    ///
    /// A bar counting files would put a four-megapixel snapshot and a
    /// hundred-megapixel export at the same weight, and its estimate would be
    /// wrong by that ratio. Advancing by megapixels is what makes the fraction
    /// drawn mean "this share of the work is done".
    #[test]
    fn the_estimate_is_weighted_by_work_and_not_by_file_count() {
        let terminal = indicatif::InMemoryTerm::new(6, 90);
        let progress = Progress::to_target(
            "Analysing 2 of 2 files",
            104,
            ProgressDrawTarget::term_like_with_hz(Box::new(terminal.clone()), 255),
        );

        // The small file of the pair: one file of two, but a twenty-sixth of
        // the work. The assertion that matters is the second one — a bar
        // counting files would read 50% here, and the estimate a user acted on
        // would be wrong by an order of magnitude.
        progress.advance(4);
        progress.redraw();
        let drawn = terminal.contents();
        assert!(drawn.contains("4%"), "got: {drawn}");
        assert!(!drawn.contains("50%"), "got: {drawn}");

        progress.advance(100);
        progress.redraw();
        assert!(
            terminal.contents().contains("100%"),
            "got: {}",
            terminal.contents()
        );
    }

    /// The label of the extraction indicator says nothing about a stage.
    ///
    /// A guard against the obvious future edit: someone adding "decrypting" or
    /// "trying the second hypothesis" here would undo the property the whole
    /// extraction path is built around, and would do it in a one-word change
    /// that looks like an improvement.
    #[test]
    fn the_activity_label_names_no_stage() {
        let forbidden = [
            "decrypt",
            "password",
            "key",
            "salt",
            "hypothesis",
            "payload",
            "header",
            "extract",
            "authenticat",
            "verify",
        ];

        let label = WORKING_LABEL.to_lowercase();
        for term in forbidden {
            assert!(
                !label.contains(term),
                "the label must reveal no stage, found {term:?} in {WORKING_LABEL:?}"
            );
        }
    }
}
