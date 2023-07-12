import typing
import dns.name
import dns.resolver
import dns.exception
import dns.rdatatype
import dataclasses
from certbot import configuration
from certbot import errors


@dataclasses.dataclass
class CAAIssue:
    issuer: bytes
    parameters: typing.Dict[bytes, typing.Optional[bytes]]

    @classmethod
    def parse(cls, value: bytes):
        issuer, *parameters = value.split(b";")
        parameters_out = {}

        for p in parameters:
            parts = p.split(b"=", 1)
            if len(parts) == 1:
                parameters_out[parts[0].strip()] = None
            else:
                parameters_out[parts[0].strip()] = parts[1].strip()

        return cls(
            issuer=issuer.strip(),
            parameters=parameters_out
        )

    def get_property(self, tag: bytes, default=None):
        if tag in self.parameters:
            return self.parameters[tag]
        else:
            return default


@dataclasses.dataclass
class Issuer:
    issuer: bytes
    priority: int

    def __eq__(self, other):
        return self.issuer == other.issuer

    def __hash__(self):
        return hash(self.issuer)


def auto_discover_server(
    config: configuration.NamespaceConfig
) -> typing.List[bytes]:
    resolver = dns.resolver.Resolver()

    domains = []

    for domain in config.domains:
        try:
            domain = dns.name.from_text(domain)
        except dns.exception.DNSException as e:
            raise errors.Error(f"Failed to parse domain {domain}: {e}")

        if domain.is_wild():
            name = domain.parent()
        else:
            name = domain

        rr = None
        while name != dns.name.root:
            try:
                rr = resolver.resolve(
                    name, dns.rdatatype.CAA, raise_on_no_answer=False
                ).rrset
                if rr:
                    break

                name = name.parent()
            except dns.exception.DNSException as e:
                raise errors.Error(f"Failed to resolve CAA record for {name}: {e}")

        if not rr:
            raise errors.Error(f"No CAA records found for {domain}")

        rr = rr.processing_order()
        issue_wild_set = list(
            map(
                lambda r: CAAIssue.parse(r.value),
                filter(lambda r: r.tag == b"issuewild", rr)
            )
        )
        issue_set = list(
            map(
                lambda r: CAAIssue.parse(r.value),
                filter(lambda r: r.tag == b"issue", rr)
            )
        )
        if domain.is_wild():
            if issue_wild_set:
                relevant_set = issue_wild_set
            elif issue_set:
                relevant_set = issue_set
            else:
                raise errors.Error(f"No CAA records found for {domain}")
        else:
            if issue_set:
                relevant_set = issue_set
            else:
                raise errors.Error(f"No CAA records found for {domain}")

        issuers = []
        for rr in relevant_set:
            if rr.get_property(b"discovery", b"true") != b"true":
                continue

            priority = rr.get_property(b"priority")
            if priority is None:
                priority = 0
            else:
                try:
                    priority = int(priority)
                except ValueError:
                    raise errors.Error(f"Invalid priority for {domain}: {priority}")

                if priority < 1:
                    raise errors.Error(f"Invalid priority for {domain}: {priority}")

            issuers.append(Issuer(issuer=rr.issuer, priority=priority))

        domains.append((domain, issuers))

    issuers_intersection = None
    for _, issuers in domains:
        if issuers_intersection is None:
            issuers_intersection = set(issuers)
        else:
            issuers_intersection.intersection_update(issuers)

    if not issuers_intersection:
        raise errors.Error("No common issuers found")

    issuers = list(map(
        lambda i: i.issuer,
        sorted(issuers_intersection, key=lambda i: i.priority)
    ))

    return issuers


def issuer_to_directory(issuer: bytes) -> str:
    try:
        issuer = issuer.decode("ascii").lower()
    except UnicodeDecodeError:
        raise errors.Error(f"Invalid issuer: {issuer}")

    return f"https://{issuer}/.well-known/acme"
