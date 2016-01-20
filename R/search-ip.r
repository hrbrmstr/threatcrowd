.search_ip <- function(ip) {

  reserr <- sGET("https://www.threatcrowd.org/searchApi/v2/ip/report/",
                 query=list(ip=ip))

  if (is.null(reserr$error)) {
    resp <- httr::warn_for_status(reserr$result)
    if (inherits(resp, "response")) {
      return(jsonlite::fromJSON(httr::content(resp, as="text",
                                              encoding="UTF-8")))
    }
  }

  return(NULL)

}

#' Search IP indicators
#'
#' @param ips character vector of IP addresses to search for
#' @param pause ThreatCrowd requests a 10s pause between requests. A higher
#'        or lower value can be specified but going lower may get your IP banned.
#' @export
#' @examples
#' search_ips("188.40.75.132")
search_ips <- function(ips, pause=10) {
  map(ips, function(x, pause) {
    res <- .search_ip(x)
    if ((pause>0) & (length(ips) > 1)) sys.sleep(pause)
    res
  }, pause=pause)
}