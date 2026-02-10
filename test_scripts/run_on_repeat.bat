@echo off

for /L %%n in (1,1,10) do (
    echo === Pass %%n ===
    for %%f in (run_basicac_test.bat run_filesystem_bfs_test.bat run_filesystem_bfsreadonly_test.bat run_lpacac_test.bat) do (
        call "%%f"
    )
)
