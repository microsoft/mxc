// Temporary type shim for @ubjs/node 0.31.0-5.
// Its JavaScript entry point exports these values, but its declarations omit them.
declare module '@ubjs/node' {
  const runtime: any;
  export default runtime;
}
