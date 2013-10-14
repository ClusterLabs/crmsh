" Vim syntax file
" Language: pacemaker-crm configuration style (http://www.clusterlabs.org/doc/crm_cli.html)
"" Filename:    pacemaker-crm.vim
"" Language:    pacemaker crm configuration text
"" Maintainer:  Lars Ellenberg <lars@linbit.com>
"" Last Change: Thu, 18 Feb 2010 16:04:36 +0100

"What to do to install this file:
" $ mkdir -p ~/.vim/syntax
" $ cp pacemaker-crm.vim ~/.vim/syntax
" to set the filetype manually, just do :setf pacemaker-crm
" TODO: autodetection logic, maybe
" augroup filetypedetect
" au BufNewFile,BufRead *.pacemaker-crm setf pacemaker-crm
" augroup END
"
"If you do not already have a .vimrc with syntax on then do this:
" $ echo "syntax on" >>~/.vimrc
"
"Now every file with a filename matching *.pacemaker-crm will be edited
"using these definitions for syntax highlighting.

" TODO: maybe add some indentation rules as well?


" For version 5.x: Clear all syntax items
" For version 6.x: Quit when a syntax file was already loaded
"if version < 600
"  syntax clear
"elseif exists("b:current_syntax")
"  finish
"endif
syn clear

syn sync lines=30
syn case ignore

syn match	crm_unexpected	/[^ ]\+/

syn match	crm_lspace	transparent /^[ \t]*/ nextgroup=crm_node,crm_container,crm_head
syn match	crm_tspace_err	/\\[ \t]\+/
syn match	crm_tspace_err	/\\\n\(primitive\|node\|group\|ms\|order\|location\|colocation\|property\).*/
syn match	crm_node	transparent /\<node \$id="[^" ]\+" \([a-z0-9.-]\+\)\?/
			\	contains=crm_head,crm_assign,crm_nodename
			\	nextgroup=crm_block

syn region	crm_block	transparent keepend contained start=/[ \t]/ skip=/\\$/ end=/$/
			\	contains=crm_assign,crm_key,crm_meta,crm_tspace_err,crm_ops
syn region	crm_order_block	transparent keepend contained start=/[ \t]/ skip=/\\$/ end=/$/
			\	contains=crm_order_ref
syn region	crm_colo_block	transparent keepend contained start=/[ \t]/ skip=/\\$/ end=/$/
			\	contains=crm_colo_ref
syn region	crm_meta	transparent keepend contained start=/[ \t]meta\>/ skip=/\\$/ end=/$/ end=/[ \t]\(params\|op\)[ \t]/
			\	contains=crm_key,crm_meta_assign

syn keyword	crm_container	contained group clone ms nextgroup=crm_id
syn keyword	crm_head	contained node
syn keyword	crm_head	contained property nextgroup=crm_block
syn keyword	crm_head	contained primitive nextgroup=crm_res_id
syn keyword	crm_head	contained location nextgroup=crm_id
syn match 	crm_id		contained nextgroup=crm_ref,crm_block /[ \t]\+\<[a-z0-9_-]\+\>/

syn keyword	crm_head	contained colocation nextgroup=crm_colo_id
syn match 	crm_colo_id	contained nextgroup=crm_colo_score /[ \t]\+\<[a-z0-9_-]\+\>/
syn match	crm_colo_score	contained nextgroup=crm_colo_block /[ \t]\+\(-\?inf\|mandatory\|advisory\|#[a-z0-9_-]\+\|[0-9]\+\):/he=e-1

syn keyword	crm_head	contained order nextgroup=crm_order_id
syn match 	crm_order_id	contained nextgroup=crm_order_score /[ \t]\+\<[a-z0-9_-]\+\>/
syn match	crm_order_score	contained nextgroup=crm_order_block /[ \t]\+\(-\?inf\|mandatory\|advisory\|#[a-z0-9_-]\+\|[0-9]\+\):/he=e-1

syn match 	crm_ref		contained nextgroup=crm_ref,crm_block /[ \t]\+\<[a-z0-9_-]\+\>/
syn match 	crm_ref		contained /[ \t]\+\<[a-z0-9_-]\+\>$/

syn match 	crm_order_ref	contained /[ \t]\+\<[a-z0-9_-]\+\>\(:\(start\|stop\|promote\|demote\)\)\?/ contains=crm_ops
syn match 	crm_colo_ref	contained /[ \t]\+\<[a-z0-9_-]\+\>\(:\(Slave\|Master\|Started\)\)\?/	contains=crm_roles

syn match 	crm_res_id	contained /[ \t]\+\<[a-z0-9_-]\+\>/ nextgroup=crm_RA
syn match	crm_RA		contained /[ \t]\+\<\(ocf:[a-z0-9_-]\+\|heartbeat\|lsb\):[a-z0-9_-]\+\>/
			\	contains=crm_ra_class,crm_ocf_vendor
			\	nextgroup=crm_block

syn match	crm_ra_class	contained /[ \t]\(ocf\|heartbeat\|lsb\)/
syn keyword	crm_ocf_vendor	contained heartbeat pacemaker linbit

syn keyword	crm_key		contained attributes params meta op operations date attributes rule
syn keyword	crm_roles	contained Master Slave Started
syn match	crm_nodename	contained / [a-z0-9.-]\+\>/
" crm_ops: match, not keyword, to avoid highlighting it inside attribute names
syn match	crm_ops		contained /\(start\|stop\|monitor\|promote\|demote\)/
syn match	crm_assign	transparent contained
	\ /[ \t]\(\$\(id\|role\|id-ref\)\|[a-z0-9_-]\+\)=\("[^"\n]*"\|[^" ]\+\([ \t]\|$\)\)/ms=s+1,me=e-1
	\ contains=crm_attr_name,crm_attr_value
syn match	crm_meta_assign	transparent contained
	\ /[ \t]\(\$\(id\|role\|id-ref\)\|[a-z0-9_-]\+\)=\("[^"\n]*"\|[^" ]\+\([ \t]\|$\)\)/ms=s+1,me=e-1
	\ contains=crm_mattr_name,crm_attr_value
syn match	crm_attr_name	contained /[^=]\+=/me=e-1
syn match	crm_mattr_name	contained /[^=]\+=/me=e-1 contains=crm_m_err
syn match	crm_m_err	contained /_/
syn match	crm_attr_value	contained /=\("[^"\n]*"\|[^" ]\+\)/ms=s+1


if !exists("did_dic_syntax_inits")
  "let did_dic_syntax_inits = 1
  hi link crm_container	Keyword
  hi link crm_head	Keyword
  hi link crm_key	Keyword
  hi link crm_id	Type
  hi link crm_colo_id	Type
  hi link crm_order_id	Type
  hi link crm_colo_score	Special
  hi link crm_order_score	Special
  hi link crm_ref	Identifier
  hi link crm_colo_ref	Identifier
  hi link crm_order_ref	Identifier
  hi link crm_res_id	Identifier
  hi link crm_nodename	Identifier
  hi link crm_attr_name Identifier
  hi link crm_mattr_name Identifier
  hi link crm_tspace_err	Error
  hi link crm_m_err	Error
  hi link crm_attr_value	String
  hi link crm_RA	Function
  hi link crm_ra_class	keyword
  hi link crm_ocf_vendor	Type
  hi link crm_unexpected	Error
  hi link crm_ops	Special
  hi link crm_roles	Special
endif

