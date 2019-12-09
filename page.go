package ufo

type Page struct {
	Path, Method string
}

func (p *Page) String() string {
	return "Path:" + p.Path + ",method:" + p.Method
}
