# To build book PDF on Ubuntu

## Preparation

- If you don't already have rust, install rust
- cargo install mdbook
- cargo install mdbook-pdf
- cargo install mdbook-mermaid
- cargo install mdbook-plantuml
- sudo apt update
- sudo apt install default-jre graphviz plantuml
- Install google chrome

## Building

- Uncomment the output.pdf line in book.toml to generate pdf
- mdbook build
- output will be in book/pdf directory

