`%p+%` <- function(x, y) { paste0(x, y, collapse="") }

sGET <- purrr::safely(httr::GET)
