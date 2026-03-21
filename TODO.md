# TODO

## Blocking

- [ ] Fix billing on `opensource-security` org — Actions are blocked by "recent account payments have failed or your spending limit needs to be increased." Need to either add a payment method or confirm Enterprise Cloud trial is active and set spending limit > $0. Once resolved, re-run PR #1 on `sift-test-app` to validate the action end-to-end.

## Next steps (from implementation plan)

- [ ] End-to-end action test on a real PR (blocked by billing above)
- [x] Add thin `store.py` to sift (optional SQLite persistence adapter)
- [ ] Set up uv in stars, add sift as git dependency
- [ ] Remove duplicated runtime modules from stars once consuming sift via uv
- [x] Named profiles in sift (`maintainer_review_v1`, `maintainer_review_fast_v1`, `maintainer_review_max_v1`)
- [ ] Flip sift to public, add README, tag v1
