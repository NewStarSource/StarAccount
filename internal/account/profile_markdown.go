package account

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	gmtext "github.com/yuin/goldmark/text"
)

var profileMarkdown = goldmark.New(goldmark.WithExtensions(extension.Table, extension.Strikethrough, extension.Footnote))

func validProfileBio(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 2000 && !strings.ContainsRune(value, 0)
}

func (app *App) profileInputError(w http.ResponseWriter, r *http.Request, field, message string) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, 400, map[string]any{"ok": false, "code": "INPUT_INVALID", "field": field, "message": message})
		return
	}
	app.respond(w, r, 400, "INPUT_INVALID", message)
}

func renderProfileMarkdown(value string) template.HTML {
	source := []byte(value)
	doc := profileMarkdown.Parser().Parse(gmtext.NewReader(source))
	// Profile introductions do not load remote or uploaded images.
	_ = ast.Walk(doc, func(node ast.Node, enter bool) (ast.WalkStatus, error) {
		if enter {
			if _, image := node.(*ast.Image); image {
				node.Parent().RemoveChild(node.Parent(), node)
				return ast.WalkSkipChildren, nil
			}
		}
		return ast.WalkContinue, nil
	})
	var output bytes.Buffer
	if profileMarkdown.Renderer().Render(&output, source, doc) != nil {
		return template.HTML(template.HTMLEscapeString(value))
	}
	// Goldmark's default renderer omits raw HTML and dangerous link destinations.
	return template.HTML(output.String())
}

func (app *App) profileMarkdownRoutes(router chi.Router) {
	router.Get("/assets/account.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(accountCSS))
	})
	router.Get("/assets/forms.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(formsJS))
	})
	router.Get("/assets/profile.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(profileJS))
	})
	router.Post("/api/v1/profile/preview", func(w http.ResponseWriter, r *http.Request) {
		identity, err := app.identity(r)
		if err != nil {
			app.internal(w, r)
			return
		}
		if identity == nil {
			app.respond(w, r, 401, "SESSION_REQUIRED", "请先登录")
			return
		}
		if r.ParseForm() != nil || !validProfileBio(r.PostForm.Get("bio")) {
			app.respond(w, r, 400, "INPUT_INVALID", "个人简介不能超过 2000 个字符")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(renderProfileMarkdown(r.PostForm.Get("bio"))))
	})
}
