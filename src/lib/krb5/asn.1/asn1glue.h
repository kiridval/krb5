/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Header file for some glue functions (macros, mostly)
 */

#include <krb5/copyright.h>

#ifndef __KRB5_GLUE_H__
#define __KRB5_GLUE_H__

#define krb5_string2qbuf(val) str2qb((val)->string, (val)->length, 1)

#define kdcoptions2KRB5_KDCOptions(val) (struct type_KRB5_KDCOptions *)flags2KRB5_TicketFlags(val)
#define KRB5_KDCOptions2kdcoptions(val) KRB5_TicketFlags2flags((struct type_KRB5_TicketFlags *) val)

#endif /* __KRB5_GLUE_H__ */
