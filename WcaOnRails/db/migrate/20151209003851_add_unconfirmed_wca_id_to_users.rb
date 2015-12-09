class AddUnconfirmedWcaIdToUsers < ActiveRecord::Migration
  def change
    add_column :users, :unconfirmed_wca_id, :string
    add_column :users, :delegate_id_to_handle_wca_id_request, :integer

    add_index :users, :delegate_id_to_handle_wca_id_request
  end
end
