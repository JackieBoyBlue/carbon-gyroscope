import os
from mongo import get_rate



# - - - - - - - - - - - - - - -  Filter and select the returned transaction data from a request  - - - - - - - - - - - - - - - - - - - - - - - - - - 

def feed_filter(data_dict) -> list:
    usable_txs = []
    usable_categories = ['BILLS_AND_SERVICES', 'EATING_OUT', 'GROCERIES', 'SHOPPING', 'TRANSPORT', 'GENERAL'] # 'ENTERTAINMENT', 'HOME', 'TRAVEL', 'FOOD_AND_DRINK', 'VEHICLES'
    for all_transactions in data_dict.values():
        for transaction in all_transactions:
            try:
                if transaction['counterPartyType'] == 'MERCHANT' and transaction['status'] == 'SETTLED' and transaction['spendingCategory'] in usable_categories: usable_txs.append(transaction)
            except: pass
    return usable_txs


class SelectDataFeed:
    
    def __init__(self, feed_txs) -> None:
        self.tx_data = {}
        for txs in feed_filter(feed_txs):
            no_apos_name = txs['counterPartyName'].replace("'", "")
            self.tx_data[txs['feedItemUid']] = (txs['amount']['minorUnits'], txs['spendingCategory'], no_apos_name, txs['transactionTime'])


    # Estimate the CO2e for each transaction and return the sum
    def estimate_carbon(self) -> float:
        carbon_list = []
        for tx in self.tx_data.values():
            pence = tx[0]
            category = tx[1]
            merchant = tx[2]
            rate = get_rate(category, merchant)
            carbon_list.append(rate * pence)
        return round(sum(carbon_list), 5)



# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - Get secret - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def get_secret():
    if os.environ.get('IN_DOCKER', False):
        with open('/run/secrets/secret_variables', 'r') as secret:
            return secret.read()
    else:
        with open('.sensitive/secrets_local.json', 'r') as secret:
            return secret.read()
