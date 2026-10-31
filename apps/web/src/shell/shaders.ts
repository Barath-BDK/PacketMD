// Ported unchanged from Crest V3.
export const NOISE = `float hs(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}
float ns(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);
  return mix(mix(hs(i),hs(i+vec2(1,0)),f.x),mix(hs(i+vec2(0,1)),hs(i+vec2(1,1)),f.x),f.y);}
float fbm(vec2 p){float v=0.,a=.5;for(int i=0;i<5;i++){v+=a*ns(p);p=p*2.03+vec2(1.7,9.2);a*=.5;}return v;}
vec3 vor(vec2 x){
  vec2 n=floor(x),f=fract(x),mg=vec2(0.),mr=vec2(0.);
  float md=8.;
  for(int j=-1;j<=1;j++)for(int i=-1;i<=1;i++){
    vec2 g=vec2(float(i),float(j));
    vec2 r=g+vec2(hs(n+g),hs(n+g+13.7))-f;
    float d=dot(r,r);
    if(d<md){md=d;mr=r;mg=g;}
  }
  md=8.;
  for(int j=-2;j<=2;j++)for(int i=-2;i<=2;i++){
    vec2 g=mg+vec2(float(i),float(j));
    vec2 r=g+vec2(hs(n+g),hs(n+g+13.7))-f;
    if(dot(mr-r,mr-r)>1e-5) md=min(md,dot(.5*(mr+r),normalize(r-mr)));
  }
  return vec3(md,n+mg);
}`;
export const FS = `#version 300 es
precision highp float;
uniform vec2 R; uniform vec2 S; uniform vec2 M;
uniform float T; uniform float Z; uniform float D; uniform float W; uniform float Mo; uniform float E; uniform float L;
uniform int V; uniform int N; uniform int NU; uniform int GA; uniform int GB;
uniform vec4 Q[10];
uniform vec3 A; uniform vec3 B;
out vec4 O;
vec2 P0; float RIP;
${NOISE}
float waveV(vec2 p,vec2 c,float fx){
  vec2 q=p+.035*vec2(fbm(p*5.+vec2(T*.07,0.)),fbm(p*5.+vec2(4.1,2.3-T*.06)));
  vec2 d=q-c;
  float a=atan(d.y,d.x);
  float b=fract((a-.1)/6.2832)*6.2832;
  float wid=.022+.125*smoothstep(0.,3.1,b);
  float r=length(d)-(.345+.006*sin(T*.5));
  float crest=exp(-r*r/(wid*wid))*smoothstep(0.,.3,b)*(1.-smoothstep(3.3,3.9,b));
  float foam=fbm(q*15.+vec2(T*.12,-T*.08))*exp(-pow((r-wid*.8)/.05,2.))*smoothstep(.2,1.,b)*(1.-smoothstep(2.6,3.5,b));
  float swell=smoothstep(.42,0.,p.y)*(.75+.25*sin(p.x*7.-p.y*5.+T*.35));
  float tri=max(0.,.33-p.y-abs(p.x-fx)*.62)*smoothstep(.13,.17,p.y);
  return crest*7.+foam*3.2+swell*4.5+fbm(q*2.2+T*.03)*.9+tri*38.;
}
float topoV(vec2 p0){
  vec2 p=p0*2.4;
  vec2 q=vec2(fbm(p+vec2(0.,T*.05)),fbm(p+vec2(5.2,1.3-T*.04)));
  return fbm(p+q*1.5)*14.;
}
vec2 contour(float v){
  if(V==3) v*=.55;
  float dd=abs(fract(v-.5)-.5)/max(fwidth(v),1e-4);
  float v2=v/5.;
  float d2=abs(fract(v2-.5)-.5)/max(fwidth(v2),1e-4);
  return vec2(1.-smoothstep(.5,1.5,dd),1.-smoothstep(.9,2.,d2));
}
// Long parallel lines: a straight ramp bent by noise, unlike Topo's closed blobs.
vec2 embers(vec2 p){
  float v=(dot(p,vec2(.82,.57))+.62*(fbm(p*1.5+vec2(T*.02,0.))-.5))*(V==3?12.:21.);
  float u=(dot(p,vec2(-.57,.82))+.4*(fbm(p*1.5+vec2(5.,T*.02))-.5))*11.-T*.22;
  float dc=length(P0-M);
  if(dc<.21*Mo) v=dc*30.;
  vec2 f=abs(fract(vec2(v,u)-.5)-.5)/max(fwidth(vec2(v,u)),1e-4);
  float core=1.-smoothstep(.5,1.6,f.x);
  float star=hs(floor(vec2(v,u)+.5)+.5)>.76?exp(-f.x*f.y*.05)*exp(-(f.x+f.y)*.03):0.;
  float tw=.6+.4*sin(T*2.+hs(floor(vec2(v,u)+.5))*40.);
  return vec2(exp(-f.x*.2)*.42,max(core*.8,star*tw*2.));
}
vec2 fissure(vec2 p,float asp){
  vec2 q=p*3.4+.25*vec2(fbm(p*3.),fbm(p*3.+4.));
  float w=fwidth(q.x)+fwidth(q.y);
  float d=vor(q).x;
  float l=1.-smoothstep(w*.4,w*1.1,d);
  float f=(1.-smoothstep(w,w*2.2,vor(q*2.7+3.).x))*.35;
  vec2 c=mix(vec2(asp*(.6+.22*sin(T*.21)),.5+.28*cos(T*.17)),M,min(Mo,1.));
  float glow=exp(-dot(p-c,p-c)/.09);
  return vec2(max(l*.62,f),l*smoothstep(.12,.8,glow)+exp(-d*d*240.)*glow*.5);
}
vec2 sonar(vec2 p,float asp){
  vec2 d=p-vec2(asp*.62,-.28);
  float r=length(d);
  vec2 g=contour(log(r+.3)*24.-T*.8+(fbm(p*2.+T*.03)-.5)*1.4);
  float arm=.35+.65*pow(fract(atan(d.y,d.x)/6.2832+T*.045),3.);
  g*=vec2(arm,mix(.4,1.,arm));
  return g*(1.-smoothstep(1.,1.9,r));
}
vec2 defense(vec2 p,float asp){
  float bd=exp(-pow(p.x/asp-(.52+.16*sin(T*.16)+(p.y-.5)*.35),2.)/.03);
  float y=p.y+.006*sin(p.x*5.+T*.4)+.01*bd*(ns(vec2(p.x*9.,T*.4))-.5);
  float fy=y*44.;
  float s=hs(vec2(floor(fy),2.));
  float ln=1.-smoothstep(.4,1.2,abs(fract(fy)-.5)/max(fwidth(fy),1e-4));
  float u=fract(p.x*(1.+s*2.)-T*(.05+.18*s)*(1.+bd*2.5)+s*9.);
  float len=.18+.22*s+.5*bd;
  float da=smoothstep(len,len-.03,u)*smoothstep(0.,.02,u)*step(.25,s);
  return vec2(ln*da*.55,ln*da*bd);
}
vec2 ridge(vec2 p,float asp){
  float x=p.x/asp,wd=1.5/R.y;
  float env=exp(-pow(x-.63,2.)/.055)*.2+.02;
  for(int i=0;i<34;i++){
    float fi=float(i);
    float h=ns(vec2(x*9.+fi*.37,fi*.21+T*.09))*.75+ns(vec2(x*23.-fi*.2,fi*.6-T*.12))*.25;
    float d=p.y-(.045+fi*.021+env*h*h*1.6);
    if(abs(d)<wd){
      float s=1.-abs(d)/wd;
      return mod(fi,5.)<.5?vec2(0.,s):vec2(s*.8,0.);
    }
    if(d<0.) return vec2(0.);
  }
  return vec2(0.);
}
// A sparse network map: hosts joined by links, with packets travelling along some of them.
vec2 npt(vec2 c){return c+.22+.56*vec2(hs(c),hs(c+13.7));}
vec2 network(vec2 p){
  vec2 q=p*6.5,id=floor(q);
  float w=fwidth(q.y)*1.1,l=0.,k=0.;
  for(int j=-1;j<=1;j++)for(int i=-1;i<=1;i++){
    vec2 c=id+vec2(float(i),float(j)),a=npt(c);
    float dn=length(q-a);
    float node=1.-smoothstep(.055,.055+w,dn);
    l=max(l,node);
    k=max(k,node*step(.82,hs(c+4.4)));
    for(int e=0;e<2;e++){
      vec2 d=e==0?vec2(1.,0.):vec2(0.,1.);
      float s=hs(c+d*7.3);
      if(s<.34) continue;
      vec2 b=npt(c+d),ab=b-a;
      float h=clamp(dot(q-a,ab)/dot(ab,ab),0.,1.);
      float ln=1.-smoothstep(0.,w,length(q-a-ab*h));
      l=max(l,ln*.5);
      if(s>.68){
        float t=fract(T*(.05+.09*s)+s*17.);
        k=max(k,1.-smoothstep(.03,.05+w,length(q-a-ab*t)));
      }
    }
  }
  return vec2(l,k);
}
vec2 layer(int g,vec2 p,vec2 c,float asp){
  if(g==0) return contour(waveV(p,c,asp*.8375)+RIP);
  if(g==1) return contour(topoV(P0)+RIP);
  if(g==2) return embers(p);
  if(g==3) return fissure(p,asp);
  if(g==4) return sonar(p,asp);
  if(g==5) return defense(p,asp);
  if(g==7) return network(p);
  return ridge(p,asp);
}
float safe(int a,int b,vec2 px){
  float m=1.;
  for(int i=a;i<b;i++){
    vec2 c=.5*(Q[i].xy+Q[i].zw),h=.5*(Q[i].zw-Q[i].xy);
    vec2 d=abs(px-c)-h;
    float e=length(max(d,0.))+min(max(d.x,d.y),0.);
    m=min(m,smoothstep(0.,R.y*.11,e));
  }
  return m;
}
void main(){
  vec2 px=gl_FragCoord.xy;
  vec2 p0=px/R.y;
  float asp=R.x/R.y;
  float xn=p0.x/asp;
  vec2 c=vec2(asp*.625,.5);
  vec2 p=(p0-c-S)/Z+c;
  float dm=length(p0-M);
  P0=p0;
  RIP=sin(dm*46.-T*3.2)*exp(-dm*dm/.018)*.42*Mo;
  vec2 lk=layer(GA,p,c,asp);
  if(W>.001) lk=mix(lk,layer(GB,p,c,asp),W);
  float l=lk.x,k=lk.y;
  float su=V==0?1.:safe(0,NU,px);
  float st=safe(NU,N,px);
  float m=1.;
  float tl=0.;
  if(V==0) m=mix(.25,1.,smoothstep(.02,.34,xn*1.6+p0.y*.35));
  if(V==1) m=smoothstep(E,E+.2,xn);
  if(V==2){
    float e2=E+.024*sin(p0.y*6.5+T*.22)+.01*sin(p0.y*17.-T*.3);
    m=smoothstep(e2,e2+.002,xn);
    tl=1.-smoothstep(.4,1.4,abs(xn-e2)*R.x);
  }
  if(V==3) m=smoothstep(.40,.54,fbm(p0*1.5+vec2(3.,T*.012)))*st*smoothstep(E-.1,E+.14,xn);
  if(V==4) m=st;
  vec3 col=mix(A,B,clamp(max(k,tl),0.,1.));
  if(L>.9) col=mix(col,vec3(1.,.86,.8),clamp(k-1.,0.,1.));
  k=min(k,1.);
  float al=max(max(l*.72,k)*m*su,tl)*D*L;
  O=vec4(col*al,al);
}`;
export const TX = `#version 300 es
precision highp float;
uniform vec2 R; uniform vec2 G; uniform float T; uniform float P; uniform int K; uniform vec3 F; uniform vec3 C;
out vec4 O;
${NOISE}
float ez(float t){t=clamp(t,0.,1.);return t*t*(3.-2.*t);}
void main(){
  vec2 p=gl_FragCoord.xy/R.y;
  float x=gl_FragCoord.x/R.x,y=gl_FragCoord.y/R.y;
  float n=(fbm(p*2.2+vec2(T*.12,-T*.08))-.2)/.6;
  float h=y+.07*sin(x*9.+T*1.4)+.03*sin(x*23.-T);
  if(K==1) h=n*.72+y*.28;
  if(K==2) h=x+.085*sin(y*5.5+T*.9)+(n-.5)*.24;
  if(K==4) h=n*.8+ns(p*14.)*.2;
  vec3 cell=K==5?vor(p*5.5+.2*vec2(fbm(p*3.),fbm(p*3.+4.))):vec3(1.);
  if(K==5) h=hs(cell.yz)*.75+x*.25;
  if(K==6) h=length(p-G)/1.6+(n-.5)*.24;
  float row=floor(y*44.);
  if(K==7) h=x*.7+y*.3+hs(vec2(row,5.))*.14;
  float band=floor(y*34.);
  if(K==8) h=x*.35+hs(vec2(band,9.))*.2+band/34.*.6;
  float a=mix(-.3,1.4,ez(P*2.));
  float b=mix(-.3,1.4,ez(P*2.-1.));
  bool hard=K==5||K==7||K==8;
  float w=hard?.0016:fwidth(h);
  float cov=smoothstep(a+w,a-w,h)*smoothstep(b-w,b+w,h);
  float c=abs(fract(h*42.-.5)-.5)/max(fwidth(h*42.),1e-4);
  float ln=1.-smoothstep(.5,1.4,c);
  if(hard) ln=0.;
  if(K==5) ln=1.-smoothstep(.006,.022,cell.x);
  if(K==8) ln=1.-smoothstep(.08,.16,abs(fract(y*34.)-.5));
  float ahead=ln*(1.-smoothstep(0.,.13,h-a))*step(a,h);
  float behind=ln*(1.-smoothstep(0.,.13,b-h))*step(h,b)*step(.5,P);
  float rw=K==4?.016:w*3.;
  float rim=1.-smoothstep(w,rw,min(abs(h-a),abs(h-b)));
  rim*=step(b-rw*1.4,h)*step(h,a+rw*1.4)*(K==5?0.:1.);
  float lines=max(max(ahead,behind),rim);
  vec3 fill=mix(F,C,ln*.13);
  float al=max(cov,lines);
  vec3 col=mix(C*lines,fill,cov);
  O=vec4(col,al);
}`;
export const VS = `#version 300 es
void main(){vec2 p=vec2(gl_VertexID==1?3.:-1.,gl_VertexID==2?3.:-1.);gl_Position=vec4(p,0.,1.);}`;
