# Contributing

Pull requests should be small enough to review and should show how they meet their acceptance criteria.

## Pull request description

Use this structure when opening a pull request:

```markdown
## Summary
- Describe the change and why it is needed.

## Acceptance criteria and evidence
| Acceptance criterion | Implementation evidence | Test or other evidence |
| --- | --- | --- |
| Copy the criterion from the issue. | Link the relevant code or explain the behavior. | Link the test and state what it verifies. |

## Verification
- `command`: passed/failed, with relevant details.

Closes #<issue-number>
```

For each criterion, give concrete evidence that a reviewer can check in the diff or by running a test. Report failures and limits accurately; do not describe a criterion as met if its evidence does not establish it.
