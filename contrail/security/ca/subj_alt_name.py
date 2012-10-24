"""Certificate Authority utilities to support X.509 SubjectAltNames using
pyasn1

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from pyasn1.type import univ, constraint, char, namedtype
from pyasn1.type import tag

MAX = 64


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'teletexString', char.TeletexString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType(
            'printableString', char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType(
            'universalString', char.UniversalString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType(
            'utf8String', char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType(
            'bmpString', char.BMPString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType(
            'ia5String', char.IA5String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        )


class AttributeValue(DirectoryString):
    pass


class AttributeType(univ.ObjectIdentifier):
    pass


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue()),
        )


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence()),
        )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString()),
        )


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        # namedtype.NamedType('otherName', AnotherName()),
        namedtype.NamedType('rfc822Name', char.IA5String().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))),
        namedtype.NamedType('dNSName', char.IA5String().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 2))),
        # namedtype.NamedType('x400Address', ORAddress()),
        namedtype.NamedType('directoryName', Name().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 4))),
        # namedtype.NamedType('ediPartyName', EDIPartyName()),
        namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 6))),
        namedtype.NamedType('iPAddress', univ.OctetString().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 7))),
        namedtype.NamedType('registeredID', univ.ObjectIdentifier().subtype(
                            implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 8))),
        )


class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class SubjectAltName(GeneralNames):
    pass

