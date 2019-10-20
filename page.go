package ufo

type Page struct {
	path, method string
}

func (p *Page) String() string {
	return "Path:" + p.path + ",method:" + p.method
}
