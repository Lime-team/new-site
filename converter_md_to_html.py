import markdown


def md_to_html(md, post_name):
    md = markdown.markdown(md)

    file_name = '/static/blog_files' + post_name + '.html'

    print(file_name)

    with open(file_name, 'w') as f:
        f.write(md)
