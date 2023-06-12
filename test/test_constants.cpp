#include <catch2/catch_all.hpp>

#include "constants.h"

TEST_CASE("Test constants")
{
    using namespace securefs;
    CHECK((kOptionNoAuthentication & kOptionReadOnly) == 0);
    CHECK((kOptionNoAuthentication & kOptionStoreTime) == 0);
    CHECK((kOptionNoAuthentication & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionNoAuthentication & kOptionNFCFileName) == 0);
    CHECK((kOptionNoAuthentication & kOptionSkipDotDot) == 0);
    CHECK((kOptionNoAuthentication & kOptionNoNameTranslation) == 0);
    CHECK((kOptionReadOnly & kOptionNoAuthentication) == 0);
    CHECK((kOptionReadOnly & kOptionStoreTime) == 0);
    CHECK((kOptionReadOnly & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionReadOnly & kOptionNFCFileName) == 0);
    CHECK((kOptionReadOnly & kOptionSkipDotDot) == 0);
    CHECK((kOptionReadOnly & kOptionNoNameTranslation) == 0);
    CHECK((kOptionStoreTime & kOptionNoAuthentication) == 0);
    CHECK((kOptionStoreTime & kOptionReadOnly) == 0);
    CHECK((kOptionStoreTime & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionStoreTime & kOptionNFCFileName) == 0);
    CHECK((kOptionStoreTime & kOptionSkipDotDot) == 0);
    CHECK((kOptionStoreTime & kOptionNoNameTranslation) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionNoAuthentication) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionReadOnly) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionStoreTime) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionNFCFileName) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionSkipDotDot) == 0);
    CHECK((kOptionCaseFoldFileName & kOptionNoNameTranslation) == 0);
    CHECK((kOptionNFCFileName & kOptionNoAuthentication) == 0);
    CHECK((kOptionNFCFileName & kOptionReadOnly) == 0);
    CHECK((kOptionNFCFileName & kOptionStoreTime) == 0);
    CHECK((kOptionNFCFileName & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionNFCFileName & kOptionSkipDotDot) == 0);
    CHECK((kOptionNFCFileName & kOptionNoNameTranslation) == 0);
    CHECK((kOptionSkipDotDot & kOptionNoAuthentication) == 0);
    CHECK((kOptionSkipDotDot & kOptionReadOnly) == 0);
    CHECK((kOptionSkipDotDot & kOptionStoreTime) == 0);
    CHECK((kOptionSkipDotDot & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionSkipDotDot & kOptionNFCFileName) == 0);
    CHECK((kOptionSkipDotDot & kOptionNoNameTranslation) == 0);
    CHECK((kOptionNoNameTranslation & kOptionNoAuthentication) == 0);
    CHECK((kOptionNoNameTranslation & kOptionReadOnly) == 0);
    CHECK((kOptionNoNameTranslation & kOptionStoreTime) == 0);
    CHECK((kOptionNoNameTranslation & kOptionCaseFoldFileName) == 0);
    CHECK((kOptionNoNameTranslation & kOptionNFCFileName) == 0);
    CHECK((kOptionNoNameTranslation & kOptionSkipDotDot) == 0);
}
