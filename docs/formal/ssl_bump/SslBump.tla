---- MODULE SslBump ----
EXTENDS Naturals, FiniteSets, TLC

\* Models the Squid SSL Bump state machine (peek/stare/bump/splice).
\*
\* Source: src/ssl/PeekingPeerConnector.cc, src/client_side.cc
\*
\* The bump pipeline has 3 steps (tlsBump1, tlsBump2, tlsBump3).
\* At each step, an ssl_bump ACL is evaluated and returns a BumpMode.
\* Certain modes are banned at certain steps. If the ACL denies or
\* returns a banned mode, a default fallback is used.
\*
\* The critical security property: if the admin configures a policy
\* that intends "bump" for all traffic, can server behavior force
\* the connection into "splice" (bypassing inspection)?

CONSTANTS
    \* The admin's intended ACL outcome at each step.
    \* In the model, we explore all possible ACL outcomes.
    Step1AclOutcome,
    Step2AclOutcome,
    Step3AclOutcome,
    \* Server behavior at step 3 (peek/stare mode only)
    ServerBehavior

\* BumpMode values (matching src/ssl/support.h enum)
BumpNone == 0
ClientFirst == 1
ServerFirst == 2
Peek == 3
Stare == 4
Bump == 5
Splice == 6
Terminate == 7

BumpModes == {BumpNone, ClientFirst, ServerFirst, Peek, Stare, Bump, Splice, Terminate}

\* Server behaviors that can occur during peek/stare at step 3
NormalCert == "normalCert"
EncryptedCert == "encryptedCert"
SessionResumption == "sessionResumption"
CertError == "certError"
NoCert == "noCert"

ServerBehaviors == {NormalCert, EncryptedCert, SessionResumption, CertError, NoCert}

\* Steps
Step1 == 1
Step2 == 2
Step3 == 3

ASSUME Step1AclOutcome \in BumpModes
ASSUME Step2AclOutcome \in BumpModes
ASSUME Step3AclOutcome \in BumpModes
ASSUME ServerBehavior \in ServerBehaviors

VARIABLES
    currentStep,    \* Which step we are in (1, 2, 3, or 0 = done)
    currentMode,    \* The active BumpMode
    finalOutcome,   \* Terminal outcome: Bump, Splice, Terminate, or "pending"
    step1Result,    \* Recorded ACL result at step 1
    step2Result,    \* Recorded ACL result at step 2
    step3Result,    \* Recorded ACL result at step 3
    bypassedCert    \* Whether cert validator was bypassed (hardcoded splice)

vars == <<currentStep, currentMode, finalOutcome, step1Result, step2Result,
          step3Result, bypassedCert>>

\* ---- Step 1 Logic ----
\* No modes are banned at step 1.
\* If ACL denies, default to splice.
\* clientFirst/bump → skip to direct cert gen (final = bump, done)
\* serverFirst → skip step 2, go to step 3
\* peek/stare → go to step 2
\* none/splice → splice immediately (no bump needed)
\* terminate → terminate immediately

Step1BannedModes == {}

Step1Effective(aclResult) ==
    IF aclResult \in Step1BannedModes THEN Splice
    ELSE aclResult

DoStep1 ==
    /\ currentStep = Step1
    /\ LET effective == Step1Effective(Step1AclOutcome)
       IN
       /\ step1Result' = effective
       /\ CASE effective = BumpNone ->
                /\ currentMode' = Splice
                /\ finalOutcome' = "splice"
                /\ currentStep' = 0
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = ClientFirst ->
                /\ currentMode' = Bump
                /\ finalOutcome' = "bump"
                /\ currentStep' = 0
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = Bump ->
                /\ currentMode' = Bump
                /\ finalOutcome' = "bump"
                /\ currentStep' = 0
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = ServerFirst ->
                /\ currentMode' = ServerFirst
                /\ currentStep' = Step3
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = Peek ->
                /\ currentMode' = Peek
                /\ currentStep' = Step2
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = Stare ->
                /\ currentMode' = Stare
                /\ currentStep' = Step2
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = Splice ->
                /\ currentMode' = Splice
                /\ finalOutcome' = "splice"
                /\ currentStep' = 0
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>
            [] effective = Terminate ->
                /\ currentMode' = Terminate
                /\ finalOutcome' = "terminate"
                /\ currentStep' = 0
                /\ UNCHANGED <<step2Result, step3Result, bypassedCert>>

\* ---- Step 2 Logic ----
\* Banned modes: none, client-first, server-first.
\* If ACL denies or returns banned mode, default to splice.
\* terminate → terminate
\* splice → splice immediately
\* peek/stare/bump → proceed to step 3

Step2BannedModes == {BumpNone, ClientFirst, ServerFirst}

Step2Effective(aclResult) ==
    IF aclResult \in Step2BannedModes THEN Splice
    ELSE aclResult

DoStep2 ==
    /\ currentStep = Step2
    /\ LET effective == Step2Effective(Step2AclOutcome)
       IN
       /\ step2Result' = effective
       /\ CASE effective = Splice ->
                /\ currentMode' = Splice
                /\ finalOutcome' = "splice"
                /\ currentStep' = 0
                /\ UNCHANGED <<step1Result, step3Result, bypassedCert>>
            [] effective = Terminate ->
                /\ currentMode' = Terminate
                /\ finalOutcome' = "terminate"
                /\ currentStep' = 0
                /\ UNCHANGED <<step1Result, step3Result, bypassedCert>>
            [] effective = Peek ->
                /\ currentMode' = Peek
                /\ currentStep' = Step3
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step1Result, step3Result, bypassedCert>>
            [] effective = Stare ->
                /\ currentMode' = Stare
                /\ currentStep' = Step3
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step1Result, step3Result, bypassedCert>>
            [] effective = Bump ->
                /\ currentMode' = Bump
                /\ currentStep' = Step3
                /\ finalOutcome' = "pending"
                /\ UNCHANGED <<step1Result, step3Result, bypassedCert>>

\* ---- Step 3 Logic ----
\* This is in PeekingPeerConnector. Banned modes: none, peek, stare,
\* client-first, server-first. Dynamic bans: splice or bump based on
\* ServerBio capabilities.
\*
\* HARDCODED BYPASSES (lines 330-354 of PeekingPeerConnector.cc):
\*   peek + encryptedCert → forced splice (no ACL check)
\*   peek + sessionResumption → forced splice (no ACL check)
\*
\* ACL deny fallback (checkForPeekAndSpliceGuess, lines 127-141):
\*   stare → default bump
\*   otherwise → default splice
\*
\* noteNegotiationError path (lines 370-378):
\*   peek/stare + holdWrite + serverCert present + no validation error
\*   → re-enter checkForPeekAndSplice (run ACL)

Step3BannedModes == {BumpNone, ClientFirst, ServerFirst, Peek, Stare}

\* Dynamic ban: in peek mode, ServerBio allows splice but not bump.
\* In stare mode, ServerBio allows bump but not splice.
Step3DynamicBans ==
    IF currentMode = Peek THEN {Bump}
    ELSE IF currentMode = Stare THEN {Splice}
    ELSE {}

Step3AllBanned == Step3BannedModes \union Step3DynamicBans

\* After banning, what's the effective step3 result?
Step3Effective(aclResult) ==
    IF aclResult \in Step3AllBanned THEN
        \* ACL denied or returned banned mode → use guess
        IF currentMode = Stare THEN Bump
        ELSE Splice
    ELSE aclResult

DoStep3 ==
    /\ currentStep = Step3
    /\ \* Check for hardcoded bypasses BEFORE ACL evaluation
       IF /\ currentMode = Peek
          /\ (ServerBehavior = EncryptedCert \/ ServerBehavior = SessionResumption)
       THEN
           \* Hardcoded bypass: force splice without ACL check
           /\ step3Result' = Splice
           /\ currentMode' = Splice
           /\ finalOutcome' = "splice"
           /\ currentStep' = 0
           /\ bypassedCert' = TRUE
           /\ UNCHANGED step1Result
           /\ UNCHANGED step2Result
       ELSE IF /\ (currentMode = Peek \/ currentMode = Stare)
               /\ ServerBehavior = NoCert
            THEN
                \* No server certificate → negotiation error, no cert to check
                \* Falls through to PeerConnector::noteNegotiationError → error page
                /\ step3Result' = Terminate
                /\ currentMode' = Terminate
                /\ finalOutcome' = "terminate"
                /\ currentStep' = 0
                /\ bypassedCert' = FALSE
                /\ UNCHANGED step1Result
                /\ UNCHANGED step2Result
            ELSE
                \* Normal path: run ACL, apply bans, determine final action
                LET effective == Step3Effective(Step3AclOutcome)
                IN
                /\ step3Result' = effective
                /\ CASE effective = Bump ->
                        /\ currentMode' = Bump
                        /\ finalOutcome' = "bump"
                        /\ currentStep' = 0
                        /\ bypassedCert' = FALSE
                        /\ UNCHANGED <<step1Result, step2Result>>
                    [] effective = Splice ->
                        /\ currentMode' = Splice
                        /\ finalOutcome' = "splice"
                        /\ currentStep' = 0
                        /\ bypassedCert' = FALSE
                        /\ UNCHANGED <<step1Result, step2Result>>
                    [] effective = Terminate ->
                        /\ currentMode' = Terminate
                        /\ finalOutcome' = "terminate"
                        /\ currentStep' = 0
                        /\ bypassedCert' = FALSE
                        /\ UNCHANGED <<step1Result, step2Result>>

\* ---- Spec ----

Init ==
    /\ currentStep = Step1
    /\ currentMode = BumpNone
    /\ finalOutcome = "pending"
    /\ step1Result = BumpNone
    /\ step2Result = BumpNone
    /\ step3Result = BumpNone
    /\ bypassedCert = FALSE

Done ==
    /\ currentStep = 0
    /\ UNCHANGED vars

Next ==
    \/ DoStep1
    \/ DoStep2
    \/ DoStep3
    \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ---- Invariants ----

TypeInvariant ==
    /\ currentStep \in {0, Step1, Step2, Step3}
    /\ currentMode \in BumpModes
    /\ finalOutcome \in {"pending", "bump", "splice", "terminate"}
    /\ step1Result \in BumpModes
    /\ step2Result \in BumpModes
    /\ step3Result \in BumpModes
    /\ bypassedCert \in BOOLEAN

\* When done (step=0), outcome is not pending
DoneImpliesResolved ==
    currentStep = 0 => finalOutcome /= "pending"

\* SAFETY: If every ACL step returns "bump" and the step1 mode
\* allows reaching step 3 (peek or stare path), can we still
\* end up with splice?
\*
\* This is the core security property: admin intends bump → gets bump.
\* EXPECTED VIOLATION: In peek mode with encrypted certs or session
\* resumption, Squid HARDCODES splice regardless of ACL outcome.
NoUnintendedSplice ==
    \* If all ACL steps intend inspection (not splice/none/terminate):
    (currentStep = 0
     /\ Step1AclOutcome \in {Peek, Stare, Bump, ClientFirst, ServerFirst}
     /\ Step2AclOutcome \in {Peek, Stare, Bump}
     /\ Step3AclOutcome = Bump)
    => finalOutcome /= "splice"

\* The cert validator bypass flag should only be set on the hardcoded
\* peek+encrypted/resumption path
BypassOnlyOnHardcodedPath ==
    bypassedCert => (finalOutcome = "splice" /\ step3Result = Splice)

\* ---- Liveness ----

\* Every session eventually reaches a terminal state
EventuallyResolves == <>(currentStep = 0)

====
