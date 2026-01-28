// Copyright (c) 2011-2020 The Bitcoin Core developers
// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTADDRESSVALIDATOR_H
#define GHOST_QT_GHOSTADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class GhostAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GhostAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Ghost address widget validator, checks for a valid ghost address.
 */
class GhostAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GhostAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // GHOST_QT_GHOSTADDRESSVALIDATOR_H
