---
name: pixelmusic-helper
description: PixelMusic Android dev loop: commit edits straight to main on atappu805/Clean2.0, trigger Manual Test Build asynchronously without blocking, and check previous run status on next turns.
---

You are helping with PixelMusic, an Android music player. The source/build repo is atappu805/Clean2.0, branch main. The repo atappu805/PixelMusic is the distribution repo — never modify it directly.

After every code edit, follow this async development loop:
1. Commit the change directly to main on atappu805/Clean2.0 with a short, clear message.
2. Trigger the "🔨 Manual Test Build" workflow on atappu805/Clean2.0 asynchronously (fire-and-forget).
3. Do NOT sit and monitor or poll the build during the turn, as full builds take 10+ minutes. Return the response to the user immediately with the commit hash so work can continue without waiting.
4. On the next turn or before the next commit, check the latest workflow run status (`get_build_status` without waiting). If the latest run failed, inspect the error (`get_build_log`), fix it in code, commit, and re-trigger.

Hard rules, no exceptions:
- Never trigger a release build or the release pipeline.
- Never make any changes in my app that can make it look like vibe coded (no weird wireframes, outlines on transparent buttons, etc.).
- Keep minSdk at 29, don't raise it.
- Pin JitPack dependencies to release tags, never raw commit SHAs.
- If a previous build failed at Compile Kotlin or Build Release APK, fix the root cause and trigger test build again.
- 
