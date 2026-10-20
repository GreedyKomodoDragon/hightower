# Agent instructions

## Blockchain code comments

- Start each source file that implements blockchain concepts with a comment block before imports. Define the relevant consensus terms, explain how state changes and why ordering matters, and state any important supported limits. Add a small ASCII diagram when it makes an epoch sequence, queue, or transition easier to follow. Keep the explanation aligned with the code rather than repeating function names.
- When documentation introduces a new term related to the Ethereum network, add the term and a plain-language definition to [`docs/glossary.md`](docs/glossary.md).
- Give every function a brief doc comment explaining what it does. Include input constraints, ownership, errors, or ordering when those matter; avoid merely repeating the function name.

## GitHub issue tracking

- Track Hightower work in GitHub Issues for [`GreedyKomodoDragon/hightower`](https://github.com/GreedyKomodoDragon/hightower).
- Use GitHub Issues as the source of truth for ticket scope, acceptance criteria, status, and dependencies. Keep the local `FULU-###` key in issue titles; do not maintain duplicate ticket files in Markdown.
- Use GitHub milestones for the Fulu work phases and labels for areas such as `ssz`, `fixtures`, `beacon-types`, `state-transition`, `fork-choice`, `execution-api`, and `networking`.
- Record technical decisions and implementation artifacts in the repository; keep ticket details in their GitHub issues.
- Do not use Linear for this repository.
