# Contributing to Nuclei MCP Integration

First off, thank you for considering contributing to the Nuclei MCP Integration project! It's people like you that make such a project possible. We welcome any type of contribution, not just code.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please create an issue in our GitHub repository. When you are creating a bug report, please include as many details as possible. Fill out the required template; the information it asks for helps us resolve issues faster.

### Suggesting Enhancements

If you have an idea for an enhancement, please create an issue to discuss it. This allows us to coordinate our efforts and prevent duplication of work. We're always open to new ideas!

### Pull Requests

We love pull requests! For a pull request to be accepted, it should:

1.  **Follow the coding style**: Run `go fmt ./...` and `go vet ./...` before committing to ensure your code is well-formatted and free of common issues.
2.  **Include tests**: If you've added code that should be tested, please add tests.
3.  **Update documentation**: If you've changed APIs or added new configuration, update the `README.md` and any other relevant documentation.
4.  **Be atomic**: One pull request should ideally address one issue or add one self-contained feature.

## Development Setup

Please refer to the Getting Started section in the main `README.md` file for instructions on how to set up the development environment. This will ensure you have all the necessary prerequisites and can run the server for testing.

## Pull Request Process

1.  Fork the repository and create your branch from `main`.
2.  Make your changes in your forked repository.
3.  Ensure any new dependencies are added to `go.mod` by running `go mod tidy`.
4.  Update the `README.md` with details of changes to the interface, this includes new tools, configuration options, or changes in behavior.
5.  Ensure your code is well-commented, especially in hard-to-understand areas.
6.  Push your changes to your fork and submit a pull request to the main repository.
7.  A project maintainer will review your pull request. You may be asked to make changes before it can be merged.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior. (Note: A `CODE_OF_CONDUCT.md` file should be created).

## License

By contributing to the Nuclei MCP Integration project, you agree that your contributions will be licensed under its MIT License. You can find the full license text in the LICENSE file.