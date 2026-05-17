from __future__ import annotations

import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class MascotState(str, Enum):
    START = "START"
    LOGS_ADDED = "LOGS_ADDED"
    PCAPS_ADDED = "PCAPS_ADDED"
    FOLDER_SELECTED = "FOLDER_SELECTED"
    ANALYZING = "ANALYZING"
    DONE = "DONE"
    ERROR = "ERROR"


@dataclass
class MascotRender:
    """What the GUI needs to draw right now."""
    state: MascotState
    pose_id: str
    frame_index: int
    frame_text: str
    bubble_text: str
    is_idle_interrupt: bool = False


def _now() -> float:
    return time.time()


class MascotEngine:
    """
    Behavior-first mascot:
    - per-state animation frames (placeholder text in r01)
    - per-state step comment pool (5)
    - idle interrupt: after 60s without state change -> 10s special pose + waiting comment
    - "you're so good at everything you do..." inside joke variants with cooldown
    """

    IDLE_TRIGGER_S = 60.0
    IDLE_DURATION_S = 10.0

    # How often we allow "ambient" chatter while sitting in a state (besides idle interrupt)
    AMBIENT_MIN_S = 18.0
    AMBIENT_MAX_S = 32.0

    # Inside joke tuning
    INSIDE_JOKE_STEP_CHANCE = 0.08   # ~1/12
    INSIDE_JOKE_IDLE_CHANCE = 0.16   # ~1/6
    INSIDE_JOKE_COOLDOWN_S = 120.0   # 2 minutes

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)

        self.state: MascotState = MascotState.START
        self._state_entered_at = _now()
        self._last_state_change_at = _now()

        # Animation control
        self._frame_index = 0
        self._in_idle_interrupt = False
        self._idle_started_at: Optional[float] = None

        # Comment control
        self._bubble_text = ""
        self._last_comment: str = ""
        self._next_ambient_at = _now() + self.rng.uniform(self.AMBIENT_MIN_S, self.AMBIENT_MAX_S)

        # Inside joke control
        self._last_inside_joke_at = 0.0

        self._step_comments: Dict[MascotState, List[str]] = self._build_step_comments()
        self._idle_comments: Dict[MascotState, List[str]] = self._build_idle_comments()
        self._inside_jokes: List[str] = self._build_inside_jokes()

        # Placeholder "poses" (art comes later)
        self._frames_by_pose: Dict[str, List[str]] = self._build_placeholder_frames()

        self.set_state(MascotState.START)

    # -------- dialogue pools --------

    def _build_inside_jokes(self) -> List[str]:
        return [
            "you're so good at everything you do…",
            "you're so good at everything you do… it’s suspicious.",
            "you're so good at everything you do… I’m gonna need a bigger ego to keep up.",
            "you're so good at everything you do… please leave some competence for the rest of us.",
            "you're so good at everything you do… alright, show-off.",
            "you're so good at everything you do… my motivational speech got cancelled.",
            "you're so good at everything you do… statistically this should be impossible.",
            "you're so good at everything you do… I checked twice. Still annoying.",
            "you're so good at everything you do… I am both proud and offended.",
        ]

    def _build_step_comments(self) -> Dict[MascotState, List[str]]:
        return {
            MascotState.START: [
                "Boot looks clean. Try not to break reality.",
                "Alright—feed me logs or PCAPs. I’m bored.",
                "We’re idle. That’s either good… or you fell asleep.",
                "Drop the evidence. I’ll do the judging.",
                "Ready when you are, operator.",
                "Console awake. Systems nominal. Drama optional.",
                "Standing by for input. Pretending patience.",
                "This dashboard is quiet. I distrust quiet.",
                "If you blink too long, I call it strategic delay.",
                "I brought sarcasm and buffer space. Let’s go.",
            ],
            MascotState.LOGS_ADDED: [
                "Logs loaded. GPS footprints acquired.",
                "Nice. The trail tells stories people regret.",
                "I see where you’ve been. Spooky.",
                "Logs look tasty. Add PCAPs for the full meal.",
                "Not bad. You’re assembling evidence like a pro.",
                "Route history imported. Breadcrumbs look sharp.",
                "Coordinates are lining up. Keep feeding me data.",
                "Log ingest clean. Timeline is starting to breathe.",
                "GPS evidence online. The map has opinions now.",
                "Good trail density. This could get precise fast.",
            ],
            MascotState.PCAPS_ADDED: [
                "PCAPs loaded. Packets are whispering.",
                "Mmm. Radio evidence. The air never lies.",
                "Good. Now we can cross-check the story.",
                "PCAPs in the bag. Want logs too?",
                "This is the fun part. Don’t blink.",
                "Frame harvest complete. Spectrum gossip acquired.",
                "RF intake looks healthy. Correlation potential rising.",
                "Packets parsed without drama. Rare and beautiful.",
                "Capture set accepted. Time to triangulate truth.",
                "PCAP payload secured. Let’s make it confess.",
            ],
            MascotState.FOLDER_SELECTED: [
                "Project folder locked. No overwrites. No tears.",
                "Good choice. Organize your chaos.",
                "Alright… everything goes in its proper vault.",
                "Folder selected. Your future self says thanks.",
                "Perfect. Now hit Analyze and pretend it’s not exciting.",
                "Vault path validated. Evidence has a home now.",
                "Storage target armed. We do clean chain-of-custody here.",
                "Folder is live. Your reports know where to land.",
                "Good housekeeping. That prevents 3 AM regret.",
                "Workspace anchored. Proceed when ready.",
            ],
            MascotState.ANALYZING: [
                "Engines lit. Parsing evidence now.",
                "Crunching frames. If this takes a bit—blame physics.",
                "Working… and yes, I’m judging your signal quality.",
                "Processing. Try not to stare at the progress bar too hard.",
                "We’re cooking. Smells like correlation.",
                "Analysis thread engaged. Hold your applause.",
                "Correlating logs to packets. This is where truth hardens.",
                "Number-crunch cycle active. Let the models eat.",
                "Indexing evidence artifacts. Precision incoming.",
                "Pipeline humming. Keep calm and trust the parse.",
            ],
            MascotState.DONE: [
                "Mission complete. Reports are in the vault.",
                "Done. That was… almost graceful.",
                "Artifacts generated. Go admire your evidence.",
                "Complete. Now go open that summary like a champion.",
                "We’re finished. Try not to get addicted to clean data.",
                "Cycle complete. Exports are waiting for your verdict.",
                "All outputs written. Nothing exploded. Historic moment.",
                "Analysis wrapped. Debrief yourself with the reports.",
                "Deliverables ready. You may now look smug.",
                "Run closed clean. Evidence story is on disk.",
            ],
            MascotState.ERROR: [
                "Bzzzt. We hit an error. Don’t panic—yet.",
                "Okay… that’s not ideal. Show me the console.",
                "Something broke. It was probably the universe, not you.",
                "Error state. I’ll act surprised: 😐",
                "Well… that wasn’t supposed to happen. But here we are.",
                "Fault detected. Grab logs before we blame ghosts.",
                "Pipeline tripped. We debug, therefore we continue.",
                "Exception intercepted. Keep breathing and read the traceback.",
                "That step failed with confidence. Let’s inspect it.",
                "Unplanned behavior observed. Diagnostics time.",
            ],
        }

    def _build_idle_comments(self) -> Dict[MascotState, List[str]]:
        base = [
            "Still with me, or did you alt-tab into the void?",
            "I can wait. I’ve got… unlimited patience. Allegedly.",
            "Take your time. The packets aren’t going anywhere.",
            "While we wait: remember—overlap between sources = confidence.",
            "If this is loading, it’s not frozen. It’s thinking. Like you. Sort of.",
            "Waiting is a phase of analysis. Don’t rush art.",
            "You want speed? Bring faster captures.",
            "If you’re stuck, check the console. It tells the truth.",
            "I’m not saying you’re slow… but the clock noticed.",
            "This silence is suspicious. I like it.",
            "Fun fact: radio evidence + GPS evidence = stronger story.",
            "Don’t worry. I’ll be here. Watching. Quietly.",
            "You could click something. I won’t stop you. Probably.",
            "Operator status: dramatic pause.",
            "I’d do a drum solo, but I’m text-based right now.",
            "Try not to add the same file twice. I will notice.",
            "If you need a moment—fine. I’ll just smolder here.",
            "We could be done already if you were… you know… magical.",
            "This is the part where a lesser tool would ‘hang’. We don’t do that here.",
            "Alright. Breathe. Then proceed.",
            "You hear that? That’s the sound of nothing happening. Beautiful.",
            "If you’re waiting for perfection—same. Forever.",
            "I’m practicing my victory pose. Don’t rush me.",
            "I can’t tell if you’re meticulous or just procrastinating stylishly.",
            "Do something cool. Like select a folder. Or hit Analyze.",
            "I’m ready when you are. Again. Always.",
            "Take your time. The evidence will still be evidence.",
            "Just a reminder: ‘no overwrite’ is a feature, not a suggestion.",
            "If you’re lost, the project folder is your anchor.",
            "We could narrate this dramatically: ‘…and then, nothing happened.’",
            "You could be scrolling reports right now. Just saying.",
            "If this is a vibe check—yes, the vibe is immaculate.",
            "Waiting… but in neon.",
            "I’m not impatient. I’m aggressively prepared.",
            "I’d offer help, but you haven’t asked. Yet.",
            "If you’re thinking—good. Thinking prevents mistakes.",
            "This tool is educational. Your attention span is the real test.",
            "I’m going to pretend you’re doing something important.",
            "Okay. I’m still here. Obviously.",
            "Let’s move. The night is young and the data is messy.",
        ]

        state_openers: Dict[MascotState, List[str]] = {
            MascotState.START: [
                "Startup lane is warm. Throw me logs or PCAPs.",
                "We are in ready-state limbo. Your move, operator.",
                "Start screen serenity. It won’t last.",
            ],
            MascotState.LOGS_ADDED: [
                "Logs are queued. Packet evidence would complete the picture.",
                "GPS side is ready; waiting on radio side.",
                "Map trail is loaded. We can go deeper.",
            ],
            MascotState.PCAPS_ADDED: [
                "Packet stack loaded. Add logs for stronger attribution.",
                "RF evidence is primed. Coordinates would sharpen it.",
                "The air has spoken; now we need the route.",
            ],
            MascotState.FOLDER_SELECTED: [
                "Vault target is set. We can safely run analysis.",
                "Folder is ready. One click from action.",
                "Storage path secured. Waiting for launch.",
            ],
            MascotState.ANALYZING: [
                "Analysis is active. Progress takes the time it takes.",
                "Engines are still chewing. Resist the urge to poke.",
                "Parser cadence steady. Let it finish clean.",
            ],
            MascotState.DONE: [
                "Run is complete. Reports are waiting on you.",
                "Finished state detected. Debrief is the next move.",
                "Nothing left to process. Review and export if needed.",
            ],
            MascotState.ERROR: [
                "We are paused on an error. Console first, panic second.",
                "Failure latched. Gather clues, then retry.",
                "Error state still active. Diagnostics beat guessing.",
            ],
        }

        comments: Dict[MascotState, List[str]] = {}
        for state in MascotState:
            lines = state_openers.get(state, []) + base
            comments[state] = lines
        return comments

    # -------- frames (placeholder) --------

    def _build_placeholder_frames(self) -> Dict[str, List[str]]:
        # Placeholder “art” is a compact animated block. We'll swap later.
        # Each pose id maps to a list of frames; engine cycles frame_index.
        def block(label: str) -> List[str]:
            return [
                f"[{label}]  (•_• )  // waiting",
                f"[{label}]  ( •_•)  // waiting",
                f"[{label}]  (•_• )  // waiting",
                f"[{label}]  ( •_•)  // waiting",
            ]

        return {
            "POSE_START": block("START"),
            "POSE_LOGS": block("LOGS"),
            "POSE_PCAPS": block("PCAPS"),
            "POSE_FOLDER": block("FOLDER"),
            "POSE_ANALYZING": [
                "[ANALYZING]  (⌐■_■)  >>> scanning.",
                "[ANALYZING]  (⌐■_■)  >>> scanning..",
                "[ANALYZING]  (⌐■_■)  >>> scanning...",
            ],
            "POSE_DONE": [
                "[DONE]  (•_• )  Mission complete.",
                "[DONE]  ( •_•)  Mission complete.",
            ],
            "POSE_ERROR": [
                "[ERROR]  (x_x)  bzzzt!",
                "[ERROR]  (X_X)  bzzzt!!",
            ],
            "POSE_IDLE_SPECIAL": [
                "[IDLE]  (¬‿¬)  ...",
                "[IDLE]  (¬‿¬)  ..",
                "[IDLE]  (¬‿¬)  .",
                "[IDLE]  (¬‿¬)  ..",
            ],
        }

    def _pose_for_state(self, state: MascotState) -> str:
        return {
            MascotState.START: "POSE_START",
            MascotState.LOGS_ADDED: "POSE_LOGS",
            MascotState.PCAPS_ADDED: "POSE_PCAPS",
            MascotState.FOLDER_SELECTED: "POSE_FOLDER",
            MascotState.ANALYZING: "POSE_ANALYZING",
            MascotState.DONE: "POSE_DONE",
            MascotState.ERROR: "POSE_ERROR",
        }[state]

    # -------- public API --------

    def set_state(self, state: MascotState) -> None:
        if state == self.state and not self._in_idle_interrupt:
            return
        self.state = state
        self._state_entered_at = _now()
        self._last_state_change_at = _now()

        self._in_idle_interrupt = False
        self._idle_started_at = None

        self._frame_index = 0
        self._next_ambient_at = _now() + self.rng.uniform(self.AMBIENT_MIN_S, self.AMBIENT_MAX_S)

        # On state entry, pick a step comment.
        self._bubble_text = self._pick_comment(kind="step")
        self._last_comment = self._bubble_text

    def tick(self) -> MascotRender:
        """
        Call frequently (e.g., via QTimer). Returns what to draw for this tick.
        Handles:
        - animation frame advance
        - ambient chatter timing
        - idle interrupt behavior
        """
        now = _now()

        # Idle interrupt trigger
        if (not self._in_idle_interrupt) and (now - self._last_state_change_at >= self.IDLE_TRIGGER_S):
            self._in_idle_interrupt = True
            self._idle_started_at = now
            self._frame_index = 0
            self._bubble_text = self._pick_comment(kind="idle")

        # Idle interrupt end
        if self._in_idle_interrupt and self._idle_started_at is not None:
            if now - self._idle_started_at >= self.IDLE_DURATION_S:
                self._in_idle_interrupt = False
                self._idle_started_at = None
                self._frame_index = 0
                self._last_state_change_at = now  # reset idle timer

        # Ambient chatter (not the 60s interrupt; just occasional step-relevant banter)
        if (not self._in_idle_interrupt) and (now >= self._next_ambient_at):
            self._bubble_text = self._pick_comment(kind="step")
            self._next_ambient_at = now + self.rng.uniform(self.AMBIENT_MIN_S, self.AMBIENT_MAX_S)

        # Choose pose + frames
        pose_id = "POSE_IDLE_SPECIAL" if self._in_idle_interrupt else self._pose_for_state(self.state)
        frames = self._frames_by_pose.get(pose_id, ["[MASCOT]"])
        frame_text = frames[self._frame_index % len(frames)]
        self._frame_index = (self._frame_index + 1) % max(1, len(frames))

        return MascotRender(
            state=self.state,
            pose_id=pose_id,
            frame_index=self._frame_index,
            frame_text=frame_text,
            bubble_text=self._bubble_text,
            is_idle_interrupt=self._in_idle_interrupt,
        )

    # -------- comment picking --------

    def _can_use_inside_joke(self) -> bool:
        return (_now() - self._last_inside_joke_at) >= self.INSIDE_JOKE_COOLDOWN_S

    def _maybe_inside_joke(self, chance: float) -> Optional[str]:
        if not self._can_use_inside_joke():
            return None
        if self.rng.random() <= chance:
            self._last_inside_joke_at = _now()
            return self.rng.choice(self._inside_jokes)
        return None

    def _pick_comment(self, kind: str) -> str:
        assert kind in ("step", "idle")
        pool = self._step_comments[self.state] if kind == "step" else self._idle_comments[self.state]

        # Inside joke injection
        joke = self._maybe_inside_joke(self.INSIDE_JOKE_IDLE_CHANCE if kind == "idle" else self.INSIDE_JOKE_STEP_CHANCE)
        if joke:
            return joke

        # Avoid repeating the last line if possible
        if len(pool) <= 1:
            return pool[0] if pool else ""
        for _ in range(8):
            c = self.rng.choice(pool)
            if c != self._last_comment:
                self._last_comment = c
                return c
        c = self.rng.choice(pool)
        self._last_comment = c
        return c
