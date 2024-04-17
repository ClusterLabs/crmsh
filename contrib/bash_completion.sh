#-*- mode: shell-script;-*-
#
# bash completion support for crmsh.
#
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# Conceptually based on gitcompletion (http://gitweb.hawaga.org.uk/).
# Distributed under the GNU General Public License, version 2.0.
#
# To use these routines:
#
#    1) Copy this file to somewhere (e.g. ~/.crm-completion.sh).
#    2) Add the following line to your .bashrc/.zshrc:
#        source ~/.crm-completion.sh

shopt -s extglob

# The following function is based on code from:
#
#   bash_completion - programmable completion functions for bash 3.2+
#
#   Copyright © 2006-2008, Ian Macdonald <ian@caliban.org>
#             © 2009-2010, Bash Completion Maintainers
#                     <bash-completion-devel@lists.alioth.debian.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2, or (at your option)
#   any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
#   The latest version of this software can be obtained here:
#
#   http://bash-completion.alioth.debian.org/
#
#   RELEASE: 2.x

# This function can be used to access a tokenized list of words
# on the command line:
#
#       __git_reassemble_comp_words_by_ref '=:'
#       if test "${words_[cword_-1]}" = -w
#       then
#               ...
#       fi
#
# The argument should be a collection of characters from the list of
# word completion separators (COMP_WORDBREAKS) to treat as ordinary
# characters.
#
# This is roughly equivalent to going back in time and setting
# COMP_WORDBREAKS to exclude those characters.  The intent is to
# make option types like --date=<type> and <rev>:<path> easy to
# recognize by treating each shell word as a single token.
#
# It is best not to set COMP_WORDBREAKS directly because the value is
# shared with other completion scripts.  By the time the completion
# function gets called, COMP_WORDS has already been populated so local
# changes to COMP_WORDBREAKS have no effect.
#
# Output: words_, cword_, cur_.

__crm_reassemble_comp_words_by_ref()
{
        local exclude i j first
        # Which word separators to exclude?
        exclude="${1//[^$COMP_WORDBREAKS]}"
        cword_=$COMP_CWORD
        if [ -z "$exclude" ]; then
                words_=("${COMP_WORDS[@]}")
                return
        fi
        # List of word completion separators has shrunk;
        # re-assemble words to complete.
        for ((i=0, j=0; i < ${#COMP_WORDS[@]}; i++, j++)); do
                # Append each nonempty word consisting of just
                # word separator characters to the current word.
                first=t
                while
                        [ $i -gt 0 ] &&
                        [ -n "${COMP_WORDS[$i]}" ] &&
                        # word consists of excluded word separators
                        [ "${COMP_WORDS[$i]//[^$exclude]}" = "${COMP_WORDS[$i]}" ]
                do
                        # Attach to the previous token,
                        # unless the previous token is the command name.
                        if [ $j -ge 2 ] && [ -n "$first" ]; then
                                ((j--))
                        fi
                        first=
                        words_[$j]=${words_[j]}${COMP_WORDS[i]}
                        if [ $i = $COMP_CWORD ]; then
                                cword_=$j
                        fi
                        if (($i < ${#COMP_WORDS[@]} - 1)); then
                                ((i++))
                        else
                                # Done.
                                return
                        fi
                done
                words_[$j]=${words_[j]}${COMP_WORDS[i]}
                if [ $i = $COMP_CWORD ]; then
                        cword_=$j
                fi
        done
}

if ! type _get_comp_words_by_ref >/dev/null 2>&1; then
_get_comp_words_by_ref ()
{
        local exclude cur_ words_ cword_
        if [ "$1" = "-n" ]; then
                exclude=$2
                shift 2
        fi
        __crm_reassemble_comp_words_by_ref "$exclude"
        cur_=${words_[cword_]}
        while [ $# -gt 0 ]; do
                case "$1" in
                cur)
                        cur=$cur_
                        ;;
                prev)
                        prev=${words_[$cword_-1]}
                        ;;
                words)
                        words=("${words_[@]}")
                        ;;
                cword)
                        cword=$cword_
                        ;;
                esac
                shift
        done
}
fi

__crmcompadd ()
{
	local i=0
	for x in $1; do
		if [[ "$x" == "$3"* ]]; then
                    if [[ "$x" =~ .*(=|:)$ ]];then
                        if [[ "$x" =~ ^id=$ ]] && [ "$x" == "$3" ];then
                            :
                        else
			    COMPREPLY[i++]="$2$x"
                        fi
                    else
			COMPREPLY[i++]="$2$x$4"
                    fi
		fi
	done
}

# Generates completion reply, appending a space to possible completion words,
# if necessary.
# It accepts 1 to 4 arguments:
# 1: List of possible completion words.
# 2: A prefix to be added to each possible completion word (optional).
# 3: Generate possible completion matches for this word (optional).
# 4: A suffix to be appended to each possible completion word (optional).
__crmcomp ()
{
	local cur_="${3-$cur}"

	case "$cur_" in
	--*=)
		;;
	*)
		local c i=0 IFS=$' \t\n'
		for c in $1; do
			c="$c${4-}"
			if [[ $c == "$cur_"* ]]; then
				case $c in
				--*=*|*.) ;;
				*) c="$c " ;;
				esac
				COMPREPLY[i++]="${2-}$c"
			fi
		done
		;;
	esac
}

# Generates completion reply from newline-separated possible completion words
# by appending a space to all of them.
# It accepts 1 to 4 arguments:
# 1: List of possible completion words, separated by a single newline.
# 2: A prefix to be added to each possible completion word (optional).
# 3: Generate possible completion matches for this word (optional).
# 4: A suffix to be appended to each possible completion word instead of
#    the default space (optional).  If specified but empty, nothing is
#    appended.
__crmcomp_nl ()
{
	local IFS=$'\n'
	__crmcompadd "$1" "${2-}" "${3-$cur}" "${4- }"
}

__crm_compgen ()
{
	local cur_="$cur" cmd="${words[1]}"
	local pfx=""

	case "$cur_" in
	*:*)
		case "$COMP_WORDBREAKS" in
		*:*) : great ;;
		*)   pfx="${cur_%%:*}:" ;;
		esac
		cur_="${cur_##*:}"
		;;
	esac

    __crmcomp_nl "$(2>/dev/null crm --compgen "${COMP_POINT}" "${COMP_LINE}")" "$pfx" "$cur_"
}

_crm() {
    local cur words cword prev

	_get_comp_words_by_ref -n =: cur words cword prev

    for ((i=1; $i<=$cword; i++)); do
        if [[ ${words[i]} != -* ]]; then
            if [[ ${words[i-1]} != @(-f|--file|-H|--history|-D|--display|-X|-c|--cib) ]]; then
                arg="${words[i]}"
                argi=$i
                break
            fi
        fi
    done

    case $prev in
        -f|--file|-H|--history|-D|--display|-X|-c|--cib)
            # use default completion
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
		__crmcomp '-w -h -d -F -R -f --file -H --history -D --display -X -c --cib'
        return 0
    fi

	__crm_compgen
} &&
complete -o bashdefault -o default -o nospace -F _crm crm || complete -o default -o nospace -F _crm crm
