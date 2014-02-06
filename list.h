/*
 * list.h
 *
 * List handling
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2014 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef MY_LIST_H
#define MY_LIST_H

#include <stddef.h>

struct link {
	struct link *next, *prev;
};
struct list {
	struct link head;
};

void list_init(struct list *l);
void list_add_after(struct link *pos, struct link *e);
void list_add_before(struct link *pos, struct link *e);
void list_add_first(struct list *l, struct link *e);
void list_add_last(struct list *l, struct link *e);
void list_unlink(struct link *e);

#define LIST_INIT(l) { .head = { .next = &l.head, .prev = &l.head } }

#define list_for_each_entry(l, e) \
	for ((e) = (l)->head.next; (e) != &((l)->head); (e) = (e)->next)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_for_each_item(l, e, type, member)				\
	for ((e) = container_of((l)->head.next, type, member);		\
	     (&e->member) != &((l)->head);				\
	     (e) = container_of((e)->member.next, type, member))

#define list_for_each_item_safe(l, e, tmp, type, member)		\
	for ((e) = container_of((l)->head.next, type, member),		\
	       (tmp) = (e)->member.next;				\
	     (&e->member) != &((l)->head);				\
	     (e) = container_of((tmp), type, member),			\
	       (tmp) = (e)->member.next)

#endif /* MY_LIST_H */
