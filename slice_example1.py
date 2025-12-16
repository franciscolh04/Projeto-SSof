comment = request.GET["comment"]
html_output = mark_safe("<p>%s</p>" % comment)