comment = request.GET["comment"]
safe_comment = html.escape(comment)
html_output = mark_safe("<p>%s</p>" % safe_comment)