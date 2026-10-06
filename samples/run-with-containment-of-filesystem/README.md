# Run with filesystem containment

Grants the sample directory to a transient container as read-only, uses it as
the contained working directory, and proves that reading succeeds while
creating a file is blocked. Other host paths remain subject to the selected
backend's default filesystem restrictions.

## Run

From this sample's corresponding language directory:

```text
# Rust
cargo run

# .NET
dotnet run

# Node
npm --prefix ../../../sdk/node install
npm --prefix ../../../sdk/node run build
npm install
npm start
```

Expected stdout contains `filesystem read succeeded` and
`write access blocked by policy`.
