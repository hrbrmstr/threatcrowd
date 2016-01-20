.search_email <- function(email) {

  reserr <- sGET("https://www.threatcrowd.org/searchApi/v2/email/report/",
                 query=list(email=email))

  if (is.null(reserr$error)) {
    resp <- httr::warn_for_status(reserr$result)
    if (inherits(resp, "response")) {
      return(jsonlite::fromJSON(httr::content(resp, as="text",
                                              encoding="UTF-8")))
    }
  }

  return(NULL)

}

#' Search e-mail indicators
#'
#' @param emails character vector of e-mails to search for
#' @param pause ThreatCrowd requests a 10s pause between requests. A higher
#'        or lower value can be specified but going lower may get your IP banned.
#' @export
#' @examples
#' search_email("william19770319@yahoo.com")
search_email <- function(emails, pause=10) {
  map(emails, function(x, pause) {
    res <- .search_email(x)
    if ((pause>0) & (length(emails) > 1)) sys.sleep(pause)
    res
  }, pause=pause)
}