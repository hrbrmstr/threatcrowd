.search_antivirus <- function(antivirus) {

  reserr <- sGET("https://www.threatcrowd.org/searchApi/v2/antivirus/report/",
                 query=list(antivirus=antivirus))

  if (is.null(reserr$error)) {
    resp <- httr::warn_for_status(reserr$result)
    if (inherits(resp, "response")) {
      return(jsonlite::fromJSON(httr::content(resp, as="text",
                                              encoding="UTF-8")))
    }
  }

  return(NULL)

}

#' Search anti-virus indicators
#'
#' @param avs character vector of AV indicators to search for
#' @param pause ThreatCrowd requests a 10s pause between requests. A higher
#'        or lower value can be specified but going lower may get your IP banned.
#' @export
#' @examples
#' search_avs("plugx")
search_avs <- function(avs, pause=10) {
  map(avs, function(x, pause) {
    res <- .search_antivirus(x)
    if ((pause>0) & (length(avs) > 1)) sys.sleep(pause)
    res
  }, pause=pause)
}