package common

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20"
	"proxy/utils/context"
)

type Server interface {
	Start(l net.Listener)
	Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *TargetAddr, error)
	Name() string
}

type Remote interface {
	Handshake(ctx *context.Context, target *TargetAddr) (io.ReadWriter, error)
	Name() string
}

type CipherStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Chacha20Stream 加密链接
type Chacha20Stream struct {
	key     []byte
	encoder *chacha20.Cipher
	decoder *chacha20.Cipher
	conn    net.Conn
}

func NewChacha20Stream(key []byte, conn net.Conn) *Chacha20Stream {
	s := &Chacha20Stream{
		key:  key, // should be exactly 32 bytes
		conn: conn,
	}

	return s
}

func (s *Chacha20Stream) Read(p []byte) (int, error) {
	if s.decoder == nil {
		nonce := make([]byte, chacha20.NonceSizeX)
		s.conn.SetReadDeadline(time.Now().Add(time.Second * 4))
		if n, err := io.ReadAtLeast(s.conn, nonce, len(nonce)); err != nil || n != len(nonce) {
			return n, errors.New("can't read nonce from stream: " + err.Error())
		}
		s.conn.SetReadDeadline(time.Time{})
		decoder, err := chacha20.NewUnauthenticatedCipher(s.key, nonce)
		if err != nil {
			return 0, errors.New("generate decoder failed: " + err.Error())
		}
		s.decoder = decoder
	}

	n, err := s.conn.Read(p)
	if err != nil || n == 0 {
		return n, err
	}

	dst := make([]byte, n)
	pn := p[:n]
	s.decoder.XORKeyStream(dst, pn)
	copy(pn, dst)
	return n, nil
}

func (s *Chacha20Stream) Write(p []byte) (int, error) {
	if s.encoder == nil {
		var err error
		nonce := make([]byte, chacha20.NonceSizeX)
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}

		s.encoder, err = chacha20.NewUnauthenticatedCipher(s.key, nonce)
		if err != nil {
			return 0, err
		}
		s.conn.SetWriteDeadline(time.Now().Add(time.Second * 4))
		if n, err := s.conn.Write(nonce); err != nil || n != len(nonce) {
			return 0, errors.New("write nonce failed: " + err.Error())
		}
		s.conn.SetWriteDeadline(time.Time{})
	}
	dst := make([]byte, len(p))
	s.encoder.XORKeyStream(dst, p)
	return s.conn.Write(dst)
}

func (s *Chacha20Stream) Close() error {
	return s.conn.Close()
}

// TargetAddr An Addr represents an address that you want to access by proxy. Either Name or IP is used exclusively.
type TargetAddr struct {
	Name     string // fully-qualified domain name
	IP       net.IP
	Port     int
	Proto    uint16       // protocol 1: tcp 3: udp
	UdpConn  *net.UDPConn // local udp connection
	UdpAddr  *net.UDPAddr // local udp addr
	RUdpConn *net.UDPConn // remote udp connection
	RUdpAddr *net.UDPAddr // remote udp addr
}

// Return host:port string
func (a *TargetAddr) String() string {
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Host Returned host string
func (a *TargetAddr) Host() string {
	if a.IP == nil {
		return a.Name
	}
	return a.IP.String()
}

func NewTargetAddr(addr string) (*TargetAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)

	target := &TargetAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Name = host
	}
	return target, nil
}

var Body = `<!doctype html>
<html>
  <head>
    <title>JS1k 2012 - Demo 1022 - "A Rose is a Rose"</title>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content=" connect-src 'none' ; default-src 'none' ; font-src 'self' ; frame-src 'self' data: ; worker-src 'self' data: ; img-src 'self' data: ssl.google-analytics.com ; media-src data: ; object-src data: ; style-src 'self' data: 'unsafe-inline' ; script-src 'unsafe-inline' 'unsafe-eval' www.google-analytics.com ; " help="please report csp-related problems to valid demos!" > 
    <meta name="author" content="Roman Cortes">
    <meta name="description" content="JS1k 2012 demo: &quot;A Rose is a Rose&quot; -- Dedicated with all my love to my colleage and friend Antonio Afonso D.S.M.">
    <meta name="pubdate" content="20120204">
    <style>
      /* https://qfox.nl/notes/333 */
      body,html,iframe{margin:0;padding:0;border:0;width:100%;height:100%}
      iframe{position:absolute;top:0;left:0;padding-top:50px;box-sizing:border-box}
      header{position:relative;z-index:1;height:47px;padding-top:2px;border-bottom:1px solid #000;box-shadow:0 -10px 25px #ccc inset;background-color:#eee}
      aside,div,h1,p{overflow:hidden;white-space:nowrap;text-overflow:ellipsis;text-align:center;font-size:16px;font-weight:inherit;line-height:22px;padding:0;margin:0;cursor:default}
      aside,h1{display:inline}
      a{color:#000;text-decoration:none;border-bottom:1px dashed #000}
      a:hover{border-bottom:1px solid red}
      a[href="0"]{text-decoration:line-through;pointer-events:none;border-bottom:0;color:#ccc}
      .button{float:left;width:40px;height:40px;line-height:40px;text-align:center;padding:0;margin:2px 0 0 10px;border:1px solid #888;border-color:#ddd #888 #888 #ddd;font-family:sans-serif;font-size:30px;font-weight:700;cursor:pointer}
      .button:hover{color:red;border-bottom-color:#888}
      .r{margin-right:10px}
      time{display:none}
    </style>

  </head>
  <body>
	<header>
      <div>
        <p>
          <em>
            Dedicated with all my love to my colleage and friend Antonio Afonso D.S.M.
          </em>
        </p>
        <aside>
          &mdash;
          1018 bytes
          &mdash;
        </aside>
      </div>

      <a href="1019" class="button p">&Larr;</a>
      <a href="1023" class="button n">&Rarr;</a>
    </header>
    <script type="demo">
with(m=Math)C=cos,S=sin,P=pow,R=random;c.width=c.height=f=500;h=-250;function p(a,b,c){if(c>60)return[S(a*7)*(13+5/(.2+P(b*4,4)))-S(b)*50,b*f+50,625+C(a*7)*(13+5/(.2+P(b*4,4)))+b*400,a*1-b/2,a];A=a*2-1;B=b*2-1;if(A*A+B*B<1){if(c>37){n=(j=c&1)?6:4;o=.5/(a+.01)+C(b*125)*3-a*300;w=b*h;return[o*C(n)+w*S(n)+j*610-390,o*S(n)-w*C(n)+550-j*350,1180+C(B+A)*99-j*300,.4-a*.1+P(1-B*B,-h*6)*.15-a*b*.4+C(a+b)/5+P(C((o*(a+1)+(B>0?w:-w))/25),30)*.1*(1-B*B),o/1e3+.7-o*w*3e-6]}if(c>32){c=c*1.16-.15;o=a*45-20;w=b*b*h;z=o*S(c)+w*C(c)+620;return[o*C(c)-w*S(c),28+C(B*.5)*99-b*b*b*60-z/2-h,z,(b*b*.3+P((1-(A*A)),7)*.15+.3)*b,b*.7]}o=A*(2-b)*(80-c*2);w=99-C(A)*120-C(b)*(-h-c*4.9)+C(P(1-b,7))*50+c*2;z=o*S(c)+w*C(c)+700;return[o*C(c)-w*S(c),B*99-C(P(b, 7))*50-c/3-z/1.35+450,z,(1-b/1.2)*.9+a*.1, P((1-b),20)/4+.05]}}setInterval('for(i=0;i<1e4;i++)if(s=p(R(),R(),i%46/.74)){z=s[2];x=~~(s[0]*f/z-h);y=~~(s[1]*f/z-h);if(!m[q=y*f+x]|m[q]>z)m[q]=z,a.fillStyle="rgb("+~(s[3]*h)+","+~(s[4]*h)+","+~(s[3]*s[3]*-80)+")",a.fillRect(x,y,1,1)}',0)
    </script>
    <script>
      (function(){var doc=document;var header=doc.getElementsByTagName("header")[0];var firstChild=header.firstChild;var p=doc.getElementsByClassName("p")[0];var n=doc.getElementsByClassName("n")[0];header.insertBefore(p,firstChild);header.insertBefore(n,firstChild);header.appendChild(doc.getElementsByTagName("p")[0])})();
      (function reload(){var doc=document;var header=doc.getElementsByTagName("header")[0];var iframe=doc.createElement("iframe");doc.body.appendChild(iframe);var iwin=iframe.contentWindow;var idoc=iframe.contentDocument;idoc.open();idoc.close();idoc.write('<!doctype html><head><meta charset="utf-8"><body>');idoc.head.innerHTML="<style>\n"+"html, body { margin: 0; padding: 0; border: 0; width: 100%; height: 100%; }\n"+"</style>\n";idoc.body.innerHTML="\n\t\t"+"<canvas"+' id="c"'+''+"></canvas>\n"+
      (true?"<script>\x3c/script>\n":"")+"";var Audio=iwin.Audio;iwin.Audio=function(x){return new Audio(x)};if(true){var canvas=idoc.getElementsByTagName("canvas")[0];iwin.a=canvas.getContext("2d");iwin.b=idoc.body;iwin.c=canvas;var p2d=iwin.Path2D;function wrap(ctx){var fill=ctx.fill,clip=ctx.clip,stroke=ctx.stroke;ctx.scale=ctx.scale;ctx.drawFocusIfNeeded=ctx.drawFocusIfNeeded;ctx.ellipse=ctx.ellipse;ctx.fill=function(r){fill.call(ctx,r==="evenodd"?"evenodd":"nonzero")};ctx.stroke=
        function(p){if(p&&p2d&&p instanceof p2d)stroke.call(ctx,p);else stroke.call(ctx)};ctx.clip=function(p){if(p&&p2d&&p instanceof p2d)clip.call(ctx,p);else clip.call(ctx)};return ctx}if(false){var cvs=iwin.c;var cNode=cvs.cloneNode;cvs.cloneNode=function(){var clone=cNode.apply(cvs,arguments);var cloneGet=clone.getContext;clone.getContext=function(){return wrap(cloneGet.call(clone,"2d"))};return clone};var get=cvs.getContext;cvs.getContext=function(){return wrap(get.call(cvs,"2d"))}}if(true)wrap(iwin.a)}idoc.body.clientWidth;
        var demo=idoc.createElement("script");var scrpt=doc.querySelector('script[type="demo"]').textContent.replace(/m.location=m.location;/,"top.reload();");if(false)scrpt="A=0,B=0;"+scrpt;demo.textContent=scrpt;idoc.body.appendChild(demo);idoc.close();iframe.contentWindow.focus();var r=doc.createElement("div");r.innerHTML="&#8635;";r.className="button r";r.title="restart just the demo (local, without remote fetch)";window.reload=r.onclick=function(){doc.body.removeChild(iframe);r.parentElement.removeChild(r);
          iframe=null;r=null;idoc=null;header=null;reload()};var firstLine=doc.getElementsByTagName("div")[0];header.insertBefore(r,firstLine)})();
    </script>
  </body>
</html>
`
var DefaultHtml = []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html;charset=utf-8\r\nConnection: Close\r\nContent-Length: " + strconv.FormatInt(int64(len([]byte(Body))), 10) + "\r\n\r\n" + Body)
