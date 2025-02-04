require "test_helper"

class ThingsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @thing = things(:one)
  end

  test "should get index" do
    get things_url
    assert_response :success
  end

  test "should get new" do
    get new_thing_url
    assert_response :success
  end

  test "should create thing" do
    assert_difference("Thing.count") do
      post things_url, params: { thing: { name: @thing.name, price: @thing.price, quantity: @thing.quantity } }
    end

    assert_redirected_to thing_url(Thing.last)
  end

  test "should show thing" do
    get thing_url(@thing)
    assert_response :success
  end

  test "should get edit" do
    get edit_thing_url(@thing)
    assert_response :success
  end

  test "should update thing" do
    patch thing_url(@thing), params: { thing: { name: @thing.name, price: @thing.price, quantity: @thing.quantity } }
    assert_redirected_to thing_url(@thing)
  end

  test "should destroy thing" do
    assert_difference("Thing.count", -1) do
      delete thing_url(@thing)
    end

    assert_redirected_to things_url
  end
end
