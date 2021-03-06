#  This file was created by Configure. Any change made to it will be lost
#  next time configure is run.
#
SHELL = /bin/sh
PERL  = /usr/bin/perl
TEX   = tex
LATEX = latex
PDFTEX= pdftex
PDFLATEX= pdflatex

DESC          = pari.desc
TMPSUF        = .tmp
MACROS= paricfg.tex parimacro.tex
USERS_TEX=$(MACROS) appa.tex users.tex usersch1.tex usersch2.tex usersch3.tex
PARI_TEX=$(MACROS) libpari.tex appb.tex appd.tex usersch4.tex usersch5.tex usersch6.tex usersch7.tex usersch8.tex

doc all:  develop.dvi libpari.dvi parallel.dvi users.dvi tutorial.dvi tutorial-mf.dvi refcard.dvi refcard-ell.dvi refcard-nf.dvi refcard-lfun.dvi refcard-mf.dvi INSTALL.dvi
docpdf:  develop.pdf libpari.pdf parallel.pdf users.pdf tutorial.pdf tutorial-mf.pdf refcard.pdf refcard-ell.pdf refcard-nf.pdf refcard-lfun.pdf refcard-mf.pdf INSTALL.pdf

.SUFFIXES: .tex .ipf .pod .inf .dumbpod .3 .html

paricfg.tex: paricfg.tex.in
	sed -e 's/@version@/2.11.2/'\
	    -e 's!@includedir@!/home/virt/multisig/target/rls/debug/build/class_group-6ce0709d060cb5fd/out/pari/include!'\
	    -e 's!@libdir@!/home/virt/multisig/target/rls/debug/build/class_group-6ce0709d060cb5fd/out/pari/lib!'\
	    -e 's!@datadir@!/home/virt/multisig/target/rls/debug/build/class_group-6ce0709d060cb5fd/out/pari/share/pari!' paricfg.tex.in > $@

%.pdf: %.tex $(MACROS)
	$(PDFTEX) $<
tutorial-mf.pdf: tutorial-mf.tex
	$(PDFLATEX) $<

%.dvi: %.tex $(MACROS)
	$(TEX) $<
tutorial-mf.dvi: tutorial-mf.tex
	$(LATEX) $<

libpari.pdf: $(PARI_TEX) $(MACROS)
	-rm -f libpari.std
	$(PDFTEX) libpari
	$(PDFTEX) libpari
	$(MAKE) libpari.std; $(PDFTEX) libpari; rm -f libpari.std
libpari.dvi: $(PARI_TEX) $(MACROS)
	-rm -f libpari.std
	$(TEX) libpari
	$(TEX) libpari
	$(MAKE) libpari.std; $(TEX) libpari; rm -f libpari.std

develop.pdf: develop.tex $(MACROS)
	-rm -f develop.std
	$(PDFTEX) develop
	$(PDFTEX) develop
	$(MAKE) develop.std; $(PDFTEX) develop; rm -f develop.std
develop.dvi: develop.tex $(MACROS)
	-rm -f develop.std
	$(TEX) develop
	$(TEX) develop
	$(MAKE) develop.std; $(TEX) develop; rm -f develop.std

parallel.pdf: parallel.tex $(MACROS)
	-rm -f parallel.std
	$(PDFTEX) parallel
	$(PDFTEX) parallel
	$(MAKE) parallel.std; $(PDFTEX) parallel; rm -f parallel.std
parallel.dvi: parallel.tex $(MACROS)
	-rm -f parallel.std
	$(TEX) parallel
	$(TEX) parallel
	$(MAKE) parallel.std; $(TEX) parallel; rm -f parallel.std

tutorial.pdf: tutorial.tex $(MACROS)
	-rm -f tutorial.std
	$(PDFTEX) tutorial
	$(PDFTEX) tutorial
tutorial.dvi: tutorial.tex $(MACROS)
	-rm -f tutorial.std
	$(TEX) tutorial
	$(TEX) tutorial

%.std: %.idx
	sed -e 's/!\([1-9]\)!/!00\1!/'\
	    -e 's/!\([1-9][0-9]\)!/!0\1!/'\
	    -e 's/\\EFF {}/f/g'\
	  $< | env LANG=C sort -f |\
	sed -e 's/!00*\([0-9]*\)!/!\1!/' > $@;

users.dvi: $(USERS_TEX)
	-rm -f users.std
	$(TEX) users
	$(TEX) users
	$(MAKE) users.std; $(TEX) users; rm -f users.std

users.pdf: $(USERS_TEX)
	-rm -f users.std
	$(PDFTEX) users
	$(PDFTEX) users
	$(MAKE) users.std; $(PDFTEX) users; rm -f users.std

gpman: gp.1
	nroff -man gp.1 | unix2dos -ascii > gp.man

man2html: gpman.html gphelpman.html tex2mailman.html
%man.html: %.1
	man2html $< | grep -v 'Content-type:' > $@

clean:
	rm -f *.log *.dvi *.idx *.pdf *.aux *.toc *.std *.dumbpod *.3 *.tmp *.html

cleandoc: clean

veryclean: clean
	rm -f paricfg.tex gp.man

.tex.pod:
	$(PERL) gphelp -to_pod $*.tex > tmp_pod && mv tmp_pod $*.pod

.tex.dumbpod:
	$(PERL) gphelp -to_dumb_pod $*.tex > tmp_pod && mv tmp_pod $*.dumbpod

.ipf.inf:
	ipfc /INF $*.ipf

# This is for testing:
.pod.ipf:
	pod2ipf $*.pod > tmp_ipf && mv tmp_ipf $*.ipf

pari.ipf:  refcard.pod tutorial.pod usersch1.pod usersch1.pod usersch2.pod usersch3.pod appa.pod
	pod2ipf --title="PARI/GP Manual" --by-files --section-name="Getting started" --file=refcard.pod --file=tutorial.pod --section-name="User guide" --file=usersch1.pod --file=usersch2.pod --file=usersch3.pod --section-name=Appendices --file=appa.pod > tmp_ipf && mv tmp_ipf pari.ipf

dumbpod: appa.dumbpod usersch1.dumbpod usersch2.dumbpod usersch3.dumbpod

.dumbpod.html:
	pod2html --title="PARI/GP Manual, part $*" --infile=$*.dumbpod --outfile=tmp_html && mv tmp_html $*.html

manpages: dumbpod appa.3 usersch1.3 usersch2.3 usersch3.3

html: dumbpod appa.html appb.html appd.html usersch1.html usersch2.html usersch3.html usersch4.html usersch5.html usersch6.html usersch7.html usersch8.html

.dumbpod.3:
	pod2man --section=3 --center="PARI/GP Manual, part $*" --release=2.11.2 --lax $*.dumbpod > tmp_man && mv tmp_man $*.3

../src/funclist::
	@-../config/genfunclist ../src/funclist ../src/desc

../src/desc/$(DESC): ../src/funclist ../src/desc/merge_822 ../src/desc/PARI/822.pm
	cd ../src/desc && $(PERL) merge_822 ../../src/funclist > def$(TMPSUF)
	mv ../src/desc/def$(TMPSUF) $@

usersch3.tex: ../src/desc/$(DESC) ../src/desc/doc_make usersFUNCS.tex
	cat usersFUNCS.tex > usersch3$(TMPSUF)
	cd ../src/desc && $(PERL) doc_make >> ../../doc/usersch3$(TMPSUF)
	mv usersch3$(TMPSUF) $@
