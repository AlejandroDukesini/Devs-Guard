module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/text v0.3.7 // indirect
	example.com/internal v1.0.0
)

require github.com/old/lib v1.0.0

replace github.com/old/lib => github.com/new/lib v1.2.0

replace example.com/internal => ../internal

exclude (
	golang.org/x/net v0.0.1
)
