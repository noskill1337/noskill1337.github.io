# The Blog theme

### Included

1. Pagination
2. SEO tags
3. Archive Page
4. RSS
5. Sitemap

## Usage

1. Fork and Clone this repository
2. Customize your blog
3. Add a new post in `_posts/` directory with proper name format (as shown in placeholder posts)
4. Commit and push to master

## Local Build

If you want to see the changes before pushing the blog to Github, do a local build.

* [`gem install jekyll`](https://jekyllrb.com/docs/installation/#install-with-rubygems)
* `gem install jekyll-sitemap`
* `gem install jekyll-paginate`
* `gem install jekyll-seo-tag`
* (`cd` to the blog directory, then:) `jekyll serve`
* Go to `http://127.0.0.1:4000/` in your web browser.

## Customizing

### Configuration variables

Edit the `_config.yml` file and set the following variables:

```yml
title: [The title of your blog]
description: [A short description of your blog's purpose]
author:
  name: [Joshua Lehr]
  email: [joshua.lehr@cyfire.net]
  url: [https://noskill1337.github.io]

baseurl: [https://noskill1337.github.io]

paginate: [Number of posts in one paginated section (default: 3)]
owner: [Joshua Lehr]
year: [Current Year]
```

*Note: All links in the site are prepended with `baseurl`. Default `baseurl` is `/`. Any other baseurl can be setup like `baseurl: /hacker-blog`, which makes the site available at `http://domain.name/hacker-blog`.*

Additionally, you may choose to set the following optional variables:

### About Page

Edit `about.md`

### Layout

If you would like to modify the site style:

**HTML**

Footer: Edit `_includes/footer.html`
Header: Edit `_includes/header.html`
Links in the header: Edit `_includes/links.html`
Meta tags, blog title display, and additional CSS: Edit `_includes/head.html`
Index page layout: Edit `_layouts/default.html`

Post layout: Edit `_layouts/post.html`

**CSS**

Site wide CSS: Edit `_sass/base.scss`

Custom CSS: Make `_sass/custom.scss` and use it. Then add `@import "custom";` to `css/main.scss`

**404 page**

Edit `404.md`

## Disclaimer / License

The information provided is released "as is" without warranty of any kind. The publisher disclaims all warranties, either express or implied, including all warranties of merchantability. No responsibility is taken for the correctness of this information. In no event shall the publisher be liable for any damages whatsoever including direct, indirect, incidental, consequential, loss of business profits or special damages, even if the publisher has been advised of the possibility of such damages.

The contents of this advisory are copyright (c) 2019 Cyfire UG and may be distributed freely provided that no fee is charged for this distribution and proper credit is given.

CC0 1.0 Universal