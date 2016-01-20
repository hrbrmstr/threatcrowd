.search_domain <- function(domain) {

  reserr <- sGET("https://www.threatcrowd.org/searchApi/v2/domain/report/",
                 query=list(domain=domain))

  if (is.null(reserr$error)) {
    resp <- httr::warn_for_status(reserr$result)
    if (inherits(resp, "response")) {
      return(jsonlite::fromJSON(httr::content(resp, as="text",
                                              encoding="UTF-8")))
    }
  }

  return(NULL)

}

#' Search domain indicators
#'
#' @param domains character vector of domains to search for
#' @param pause ThreatCrowd requests a 10s pause between requests. A higher
#'        or lower value can be specified but going lower may get your IP banned.
#' @export
#' @examples
#' search_domains("aoldaily.com")
search_domains <- function(domains, pause=10) {
  map(domains, function(x, pause) {
    res <- .search_domain(x)
    if ((pause>0) & (length(domains) > 1)) sys.sleep(pause)
    res
  }, pause=pause)
}