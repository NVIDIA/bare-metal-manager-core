#!/bin/bash
#
# Delete all but the most recent core file. This is called by forge-dpu-agent's ExecStartPre.
#
# - Find all files (`-type f`) directly within the specified directory (`-maxdepth 1`).
# - `-printf '%T+ %p\n'` prints the modification time and file path of each file, which allows us to sort them.
# - `sort` sorts the files by their modification time. By default, it sorts in ascending order (oldest first).
# - `head -n -1` skips the most recent file by excluding the last line of sorted output.
# - `cut -d' ' -f2-` extracts the file path part of the line, effectively ignoring the date part.
# - `xargs -r -I {} rm -v {}` calls `rm` on each file path passed to it, deleting the files. The `-r` option prevents `xargs` from running if there are no inputs.

find /var/support/core/ -maxdepth 1 -type f -printf '%T+ %p\n' | sort | head -n -1 | cut -d' ' -f2- | xargs -r -I {} rm -v {}

