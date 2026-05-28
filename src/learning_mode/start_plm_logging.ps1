$wprp = Join-Path $PSScriptRoot 'PLM.wprp'

# Discard any previous in-memory trace session before starting a new one.
# `wpr -cancel` aborts an active trace without writing the .etl, freeing
# the kernel session. If no session is active wpr returns non-zero --
# that's expected, so suppress its output and ignore the exit code.
& wpr -cancel 2>&1 | Out-Null

wpr -start "$wprp!AccessFailureProfile" -filemode