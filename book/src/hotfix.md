# Hot Fix Process

### Description

If a hot fix is needed for a production site the following steps would happen.

1. A developer would create the fix and check it into trunk the same as the current process.
2. A release manager would create a release/ branch based off the tag that is installed on the production site.
   Example: git switch -C release/v2024.04-rc1-p1 v2024.04-rc1
3. The fix from the trunk would be cherry-picked into this new branch.
4. Resolve any conflicts in the cherry-pick
5. The new branch is pushed to origin
   Example: git push --set-upstream origin release/v2024.04-rc1-p1
6. A new tag is added for this production build + hot fix
   EXample: git tag -a v2024.04-rc1-p1 -m "v2024.04-rc1-p1: Forge April release with patch 1"
7. The pipeline is kicked off manually, since the branch is prepended with release/ it will go through the same pipeline stages as trunk
8. The new build is tested
9. The hot fix is released to production
