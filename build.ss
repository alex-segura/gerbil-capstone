#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/make)

(def build-spec
  `((gxc: "core"
          "-cc-options" ,(cppflags "capstone" "")
          "-ld-options" ,(ldflags "capstone" ""))))

(def srcdir
  (path-normalize (path-directory (this-source-file))))

(def (main . args)
  (match args
    (["deps"]
     (let (build-deps (make-depgraph/spec build-spec))
       (call-with-output-file "build-deps" (cut write build-deps <>))))
    ([]
     (let (depgraph (call-with-input-file "build-deps" read))
       (make srcdir: srcdir
             debug: 'src
             optimize: #f
             static: #f
             depgraph: depgraph
             verbose: #t
             build-spec)))))
