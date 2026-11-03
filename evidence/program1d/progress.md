# Program 1d progress

## 20-minute checkpoint - 2026-11-03T23:40:55Z

Tested:

- Restored all three VMs independently for Run A and Run B.
- Reproduced S1 and confirmed descriptor cell digest
  `116a345a16a0dfe8084dc0da8c2a29a6a3c7b10ee71d5ca14c1a4349b748ef8d`
  before each enforcement check.
- Performed LDAP attempts 1a, 1b, and 1c under the legacy principal token.
- Collected SCM service-start, Security log, managed-retrieval, readback, and
  S2 cleanup observations before restoring all VMs to the baseline and
  leaving them powered off.

Observed:

- In both runs, 1a returned an LDAP referral with result code 10; 1b and 1c
  returned insufficient-access result code 50.
- Neither DC's attribute digest changed after any attempt, and S2 retained
  only the original attribute value.
- The dMSA service was configured through SCM in both windows, but start
  returned 1069 and Security recorded event 4625. RODC secure-channel reset
  returned exit 1, so the RODC-pinned service sub-observable is blocked.
- RWDC retrieval remained false before and after. The RODC retrieval
  sub-observable is blocked because RODC affinity could not be established.

Next:

- Seal the normalized two-run ledger, update discrepancy-03 and the program
  indexes, run repository verification, and open the requested pull request.
