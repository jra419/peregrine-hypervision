" auto-indenting depending on file type
filetype plugin indent on
" disable compatibility with vi
set nocompatible

if exists('+termguicolors')
	let &t_8f="\<Esc>[38;2;%lu;%lu;%lum"
	let &t_8b="\<Esc>[48;2;%lu;%lu;%lum"
	set termguicolors
endif

set term=xterm-256color

syntax on
" line numbers
set number
" backspace always working in insert mode
set backspace=indent,eol,start
" show current partial command
set showcmd
set noswapfile
" disable backup file creation
set nobackup
set nowritebackup
set encoding=utf-8
" automatically save before :next, :make, etc
set autowrite
" automatically reread changed files
set autoread
" always display the status line
set laststatus=2
" hide buffers instead of closing them
set hidden
set updatetime=100

" split vertical windows to the right
set splitright
" split horizontal windows below
set splitbelow

" always show the cursor position
set ruler
" save all buffers on focus out
au FocusLost * :wa
set ttyfast

" middle-click paste
set mouse=v
" enable mouse click
set mouse=a
set ttymouse=sgr

" highlight search
set hlsearch					
" incremental search
set incsearch					
" search is case insensitive
set ignorecase					
" except when it contains upper case characters
set smartcase					
set conceallevel=2

set nocursorcolumn
set nocursorline
set norelativenumber

set wrap
set linebreak
set breakindent
set tw=100

" q: allow formatting of comments with gq
" r: auto insert the current comment leader after hitting enter in insert mode
" n: when formatting text, recognize numbered lists
" 1: Don't break a line after a one-letter word. It's broken before it instead, if possible
set formatoptions=qrn1
"
" number of spaces that a tab in a file counts for
set tabstop=4
" multiple spaces as tabstops
set softtabstop=4
set smarttab
set shiftwidth=4
set autoindent
set smartindent
set showmatch

set nrformats-=octal
set shiftround

" time out on key code but not on mappings
set notimeout
set ttimeout
set ttimeoutlen=10

" better completion
set complete=.,w,b,u,t
set completeopt=menu,menuone,preview,noselect,noinsert

set wildmenu
" bash-like tab completion
set wildmode=longest,list

" remap split navigation
nnoremap <C-J> <C-W><C-J>
nnoremap <C-K> <C-W><C-K>
nnoremap <C-L> <C-W><C-L>
nnoremap <C-H> <C-W><C-H>

" remap gk and gj to j and k
nnoremap j gj
nnoremap k gk

" Disable arrow keys
noremap <Down> <Nop>
noremap <Left> <Nop>
noremap <Right> <Nop>
noremap <Up> <Nop>

" disable ctrl-b
noremap <C-B> <Nop>

" map shift-tab
inoremap <S-Tab> <C-d>

let mapleader = ","

" remove search highlight
nnoremap <leader><space> :nohlsearch<CR>

" buffer prev/next
nnoremap <C-x> :bnext<CR>
nnoremap <C-z> :bprev<CR>

" center next/prev search
nnoremap n nzzzv
nnoremap N Nzzzv

let g:polyglot_disabled = ['markdown']

call plug#begin(expand('~/.vim/plugged'))
	Plug 'arcticicestudio/nord-vim'
	Plug 'vim-airline/vim-airline'
	Plug 'sheerun/vim-polyglot'
	Plug 'junegunn/fzf.vim'
	Plug 'junegunn/fzf', { 'do': { -> fzf#install() } }
	Plug 'dense-analysis/ale'
	Plug 'tpope/vim-commentary'
	Plug 'tpope/vim-surround'
	Plug 'tpope/vim-fugitive'
	Plug 'lervag/wiki.vim'
	Plug 'lervag/vimtex'
	Plug 'mg979/vim-visual-multi', {'branch': 'master'}
	Plug 'airblade/vim-gitgutter'
call plug#end()

colorscheme nord
set cursorline

" highlight! link Terminal Normal
hi Normal guibg=NONE ctermbg=NONE
" hi! Search guifg=#88C0D0 guibg=#3B4252 ctermfg=6 ctermbg=0 gui=reverse term=reverse

" ==================== vim-polyglot ====================

let g:csv_no_conceal = 1

" ==================== netrw ====================

let g:netrw_banner = 0
let g:netrw_liststyle = 3
let g:netrw_browse_split = 4
let g:netrw_winsize = 20
let g:netrw_altv = 1

nnoremap <leader>n :20Lexplore<CR>

" ==================== airline ====================

if !exists('g:airline_symbols')
	let g:airline_symbols = {}
	let g:airline_symbols.notexists = '?'
endif

let g:airline_powerline_fonts=0
let g:airline#extensions#whitespace#mixed_indent_algo = 3
let g:airline_symbols.maxlinenr=''

" ==================== ale ====================

let g:ale_sign_error = '●'
let g:ale_sign_warning = '.'

let g:ale_linters = {
\	'java': [],
\	'python': ['pylsp'],
\	'c': ['clangd'],
\	'cpp': ['clangd'],
\	'latex': ['chktex'],
\   'bash': ['shellcheck']
\ }

let g:ale_python_pylsp_config={'pylsp': {
	\ 'plugins': {
	\   'ruff': {'enabled': v:true, 'lineLength': 120},
	\   'yapf': {'enabled': v:false},
	\ },
	\ }}

let g:ale_tex_chktex_options = '-n8 -n24'
let g:ale_virtualtext_cursor = 'disabled'
let g:ale_python_pylsp_use_global = 0
let g:ale_python_pylsp_options = '-vvv --log-file /tmp/lsp.log'

let g:ale_completion_enabled = 1
let g:ale_completion_delay = 50

nnoremap <leader>gf :ALEGoToDefinition<CR>
nnoremap <leader>gr :ALEFindReferences -quickfix <bar> :copen<CR>
nnoremap <leader>rn :ALERename<CR>

nnoremap <leader>l :ALEToggle<CR>

" ==================== fugitive ====================

nnoremap <leader>gs :Git<CR>

" ==================== fzf ====================

nnoremap <C-p> :Files<CR>
nnoremap <leader>b :Buffers<CR>
nnoremap <leader>rr :Rg -.<CR>

" ==================== wiki.vim  ====================

let g:wiki_root = '~/resources/wiki'
let g:wiki_global_load = 0
let g:wiki_filetypes = ['md', 'txt']
let g:wiki_link_extension = '.md'
let g:wiki_link_target_type = 'md'

" ==================== vimtex ====================

let g:tex_flavor='latex'
let g:vimtex_view_general_viewer='zathura'
let g:vimtex_quickfix_mode=0
let g:vimtex_syntax_conceal_disable=1

" ==================== vim-visual-multi ====================

let g:VM_mouse_mappings = 1

" ==================== vim-markdown ====================

" let g:markdown_fenced_languages = ['python', 'bash=sh', 'java', 'p4', 'elixir']
let g:markdown_minlines = 100
let g:vim_markdown_math = 1
