syntax on
set background=dark
set modeline
set modelines=5
set nofixendofline
set tabstop=2
set expandtab
set shiftwidth=0
set splitbelow
set splitright
set undofile
set directory=$HOME/.vim/swap//
set backupdir=$HOME/.vim/backup//
set undodir=$HOME/.vim/undo//
cnoreabbrev X x
filetype plugin indent on
try
  source $HOME/.vimrc.local
catch
  " skip
endtry
