Prepare a release:

1. Run `npm test` and `npm run build`.
2. Update CHANGELOG.md with the changes since the last tag.
3. Bump the version with `npm version $ARGUMENTS --no-git-tag-version`.
4. Show the user the diff and wait for confirmation before tagging.
