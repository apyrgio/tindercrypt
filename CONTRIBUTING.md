# How to contribute

First, read the [`NOTICE.md`] file for the legal status of the project.

You can contribute by sending a pull request as follows:

1. Fork the repository.
2. Make your changes and then run the tests with `cargo test`. For changes in
   our `.proto` files, do the following:

   * Check if the `.proto` files pass the lint checks of Uber's [`prototool`].
   * Compile the `.proto` files with `cargo build --features proto-gen`.
   * Commit the generated Rust code.

3. If your changes close any issues, specify them in the respective commits
   (`Closes #...`), and update `CHANGELOG.md` if necessary.
4. Create a pull request that targets the `master` branch.

Once you've sent a PR, wait for the CI steps to finish successfully. When the CI
and review process complete successfully, please ensure that your branch
presents a clear history of changes, i.e., squash fixup commits and update stale
commit messages. Finally, the PR will be merged with the "Rebase and merge"
strategy.

[`NOTICE.md`]: NOTICE.md
[`prototool`]: https://github.com/uber/prototool
