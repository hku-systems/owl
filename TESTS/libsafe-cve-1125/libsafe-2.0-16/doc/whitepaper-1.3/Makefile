PAPER	= whitepaper-13
TARGET	= $(PAPER).ps
PDFFILE	= $(PAPER).pdf
SRC	= $(PAPER).tex
TEX	= latex


.SUFFIXES:

CODE = t1.tex

.PRECIOUS: %.dvi

all		:	${CODE} ${TARGET}

pdf		:	$(PDFFILE)

%.ps		:	%.dvi
			dvips -o $@ $*
			cp $@ ..

%.dvi		:	${CODE} %.tex %.bbl
			latex $*

%.pdf		:	%.ps
			echo "quit" | gs -sDEVICE=pdfwrite -sOutputFile=$@ $<

%.bbl		:	${SRC} %.bib
			latex $*
			bibtex $*
			latex $*
			latex $*
#			touch $*.tex

clean		:
			\rm -f *.dvi *.log *.aux *.log *.bbl *.blg *.lof *.toc *.bak *~
			#\rm -f ${CODE}

purge		:	clean
			\rm -fr ${TARGET}

%.tex		::	%.java
			lgrind -ljava -i $< > $@  

%.tex		::	%.sh
			lgrind -lsh -i $< > $@  

%.tex		::	%.txt
			lgrind -i $< > $@  

%.tex		::	%.c
			lgrind -lc -i $< > $@  

%.tex		::	%.lg
			lgrind -e $< | sed s/\\\\Head\{\}// > $@  

